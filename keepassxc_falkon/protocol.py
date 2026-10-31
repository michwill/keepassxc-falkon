"""Client for KeePassXC's browser-integration protocol.

This is the protocol keepassxc-browser speaks (through keepassxc-proxy) —
here spoken directly to KeePassXC's local socket. Messages are flat JSON
objects; everything past the initial key exchange is encrypted with
``crypto_box`` under per-session keys, and every reply carries the
request's nonce incremented by one.

Requests are serialized: one in flight at a time. KeePassXC's error
replies carry no nonce, and a request that pops a dialog in KeePassXC
(association, access confirmation, "update entry?") answers only when
the user does — while other requests are answered meanwhile. With one
request outstanding, the next reply is always its answer.

Each operation is a generator ("job") that yields raw requests and is
resumed with the decrypted replies, so multi-step flows (key exchange →
database hash → test-associate → get-logins) read top to bottom. Jobs
run one after another. Falkon asks its password backend synchronously,
so ``wait()`` can pump a job to completion by blocking on the socket
(``waitForReadyRead``) — no nested event loop, so no re-entrancy into
Falkon while it waits.
"""

import base64
import json
import logging
import os
import time
from collections import deque
from collections.abc import Callable, Generator
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, TypeVar
from urllib.parse import urlsplit

from PySide6.QtCore import QDir, QObject, QStandardPaths, QTimer, Signal
from PySide6.QtNetwork import QLocalSocket

from . import sodium

if TYPE_CHECKING:
    from .store import Store

log = logging.getLogger("keepassxc_falkon")

SERVER_NAME = "org.keepassxc.KeePassXC.BrowserServer"

# KeePassXC's error codes (src/browser/BrowserMessageBuilder.h).
DATABASE_NOT_OPENED = 1
ACTION_CANCELLED_OR_DENIED = 6
ASSOCIATION_FAILED = 8
NO_LOGINS_FOUND = 15
# Our own, for failures that never reach KeePassXC.
NOT_RUNNING = -1
DISCONNECTED = -2
TIMEOUT = -3
NOT_ASSOCIATED = -4
PROTOCOL_ERROR = -5

# A request that can open a dialog in KeePassXC waits for the user.
INTERACTIVE_TIMEOUT_MS = 5 * 60 * 1000
QUICK_TIMEOUT_MS = 15 * 1000
# KeePassXC's answer for a site is reused this long, counted from when it
# arrives (so from the user's click if KeePassXC asked): an "Allow" without
# "Remember" isn't asked again right away, from another page of the site or
# when the page changes its address.
CACHE_TTL_S = 30
MAX_BUFFER = 8 * 1024 * 1024
# KeePassXC saves 150 ms after a change, on a worker thread, while its main
# thread keeps serving us from a nested event loop; when the save returns it
# marks the database clean. A change we make *during* that save is therefore
# kept in memory but never written, and lost at the next lock or quit
# (KeePassXC 2.8: Database::saveAs → AsyncTask::runAndWaitForFuture →
# markAsClean). So our writes keep this distance from each other; a save,
# key derivation included, takes about a second with default settings.
WRITE_SPACING_S = 3.0

T = TypeVar("T")
# A job yields wire requests (or pauses) and is resumed with the decrypted
# replies; its return value becomes the Job's result.
Steps = Generator["_Raw | _Sleep", Any, T]
Callback = Callable[["Job"], object]


class KeePassXCError(Exception):
    def __init__(self, code: int, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class Login:
    uuid: str
    login: str
    password: str
    name: str = ""
    group: str = ""
    expired: bool = False
    has_totp: bool = False

    @classmethod
    def from_json(cls, obj: dict[str, Any]) -> "Login":
        return cls(
            uuid=str(obj.get("uuid", "")),
            login=str(obj.get("login", "")),
            password=str(obj.get("password", "")),
            name=str(obj.get("name", "")),
            group=str(obj.get("group", "")),
            expired=str(obj.get("expired", "")).lower() == "true",
            # KeePassXC includes the current code; we only keep the fact, and
            # ask for a fresh code when it's needed (it changes every 30 s).
            has_totp=bool(obj.get("totp")),
        )


def socket_paths() -> list[str]:
    """Where KeePassXC may be listening (src/browser/BrowserShared.cpp)."""
    runtime = os.environ.get("XDG_RUNTIME_DIR") or QStandardPaths.writableLocation(
        QStandardPaths.StandardLocation.RuntimeLocation
    )
    paths = [
        os.path.join(runtime, "app", "org.keepassxc.KeePassXC", SERVER_NAME),
        os.path.join(runtime, SERVER_NAME),  # legacy symlink (non-Flatpak)
    ]
    snap = os.path.expanduser(os.path.join("~", "snap", "keepassxc", "common", SERVER_NAME))
    paths += [snap, os.path.join(QDir.tempPath(), SERVER_NAME)]
    return paths


def site_key(url: str) -> str:
    """The site a lookup is cached under: scheme, host and port."""
    parts = urlsplit(url)
    port = f":{parts.port}" if parts.port is not None else ""
    return f"{parts.scheme}://{parts.hostname or ''}{port}"


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.b64decode(text, validate=True)


class _Raw:
    """One request on the wire. ``plain`` marks the unencrypted key exchange."""

    def __init__(
        self,
        action: str,
        message: dict[str, Any] | None = None,
        *,
        plain: dict[str, str] | None = None,
        trigger_unlock: bool = False,
        timeout: int = QUICK_TIMEOUT_MS,
    ) -> None:
        self.action = action
        self.message = message or {}
        self.plain = plain
        self.trigger_unlock = trigger_unlock
        self.timeout = timeout
        self.expected_nonce: str | None = None


class _Sleep:
    """Yielded by a job to pause without sending anything."""

    def __init__(self, seconds: float) -> None:
        self.seconds = seconds


class Job:
    """A running operation. ``result``/``error`` are set when ``done``."""

    def __init__(self, gen: Steps[Any] | None = None) -> None:
        self._gen = gen
        self.done = False
        self.result: Any = None
        self.error: KeePassXCError | None = None
        # A synchronous caller (Falkon) already gave up waiting for it once.
        self.sync_timed_out = False
        self._callbacks: list[Callback] = []

    def then(self, callback: Callback | None) -> "Job":
        """Call ``callback(job)`` once done (from the event loop, never
        synchronously from inside a Falkon call)."""
        if callback is None:
            return self
        if self.done:
            QTimer.singleShot(0, lambda: callback(self))
        else:
            self._callbacks.append(callback)
        return self

    @classmethod
    def finished(cls, result: Any = None, error: KeePassXCError | None = None) -> "Job":
        job = cls()
        job.done, job.result, job.error = True, result, error
        return job


class KeePassXCClient(QObject):
    # Anything user-visible changed: reachability, lock state, association.
    stateChanged = Signal()
    databaseUnlocked = Signal()
    databaseLocked = Signal()

    def __init__(
        self, store: "Store", parent: QObject | None = None, paths: Callable[[], list[str]] = socket_paths
    ) -> None:
        super().__init__(parent)
        self._store = store
        self._paths = paths
        self._client_id = _b64(os.urandom(24))
        self._socket: QLocalSocket | None = None
        self._buffer = b""
        self._jobs: deque[Job] = deque()
        self._current: Job | None = None
        self._inflight: _Raw | None = None
        self._pumping = False
        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.timeout.connect(self._on_timeout)
        self._cache: dict[str, tuple[float, list[Login]]] = {}  # by site_key
        self._pending: dict[str, Job] = {}  # get-logins in progress, by site_key
        self._associate_after_unlock = False
        self._last_write: float | None = None  # when our last change was answered
        # Session state, reset whenever the connection drops.
        self._crypto: tuple[sodium.Box, bytes] | None = None  # (box, our public key)
        self._session_hash: str | None = None  # database test-associated this session
        # What we last learned, for status displays.
        self.running: bool | None = None
        self.locked: bool | None = None
        self.db_hash: str | None = None
        self.associated_id: str | None = None

    # ------------------------------------------------------------------
    # Public API — every call returns a Job; pass ``callback(job)`` or
    # block on it with ``wait()``.

    def get_logins(self, url: str, callback: Callback | None = None) -> Job:
        """The entries KeePassXC offers for ``url`` (empty if none). Answers
        from a short-lived per-site cache; concurrent asks for a site share
        one request (and so at most one KeePassXC access dialog)."""
        key = site_key(url)
        fresh = self.fresh_logins(url)
        if fresh is not None:
            return Job.finished(result=fresh).then(callback)
        job = self._pending.get(key)
        if job is None or job.done:
            job = self._submit(self._get_logins(url))
            self._pending[key] = job
            job.then(lambda _j: self._pending.pop(key, None))
        return job.then(callback)

    def fresh_logins(self, url: str) -> list[Login] | None:
        """KeePassXC's answer for the site if it's recent enough to reuse
        without asking again (``CACHE_TTL_S``); None otherwise."""
        hit = self._cache.get(site_key(url))
        return hit[1] if hit is not None and time.monotonic() - hit[0] < CACHE_TTL_S else None

    def cached_logins(self, url: str) -> list[Login] | None:
        """The last answer for the site, however old: for display only."""
        hit = self._cache.get(site_key(url))
        return hit[1] if hit is not None else None

    def save_login(
        self,
        url: str,
        login: str,
        password: str,
        uuid: str | None = None,
        *,
        trigger_unlock: bool = False,
        callback: Callback | None = None,
    ) -> Job:
        """Create or update an entry. Without ``uuid``, an existing entry
        with the same username is updated rather than duplicated. Result:
        ``"added"``, ``"updated"``, ``"unchanged"`` or ``"declined"``."""
        return self._submit(self._save_login(url, login, password, uuid, trigger_unlock)).then(callback)

    def get_totp(self, uuid: str, callback: Callback | None = None) -> Job:
        """The entry's current TOTP code (empty if it has none)."""
        return self._submit(self._get_totp(uuid)).then(callback)

    def passkeys(self, kind: str, public_key: dict[str, Any], origin: str, callback: Callback | None = None) -> Job:
        """Register (``kind == "create"``) or use (``"get"``) a passkey.
        KeePassXC validates ``origin`` against the relying party, asks the
        user, and answers with the credential, or with ``{"errorCode": n}``."""
        action = "passkeys-register" if kind == "create" else "passkeys-get"
        return self._submit(self._passkeys(action, public_key, origin)).then(callback)

    def associate(self, callback: Callback | None = None) -> Job:
        """Connect to the open database (KeePassXC asks the user to name the
        connection). Asks KeePassXC to unlock first if needed, and retries
        once the database is unlocked."""
        return self._submit(self._associate()).then(callback)

    def unlock(self, callback: Callback | None = None) -> Job:
        """Ask KeePassXC to show its unlock dialog (no-op if unlocked)."""
        return self._submit(self._unlock()).then(callback)

    def status(self, callback: Callback | None = None) -> Job:
        """Probe without prompting: result is a dict for status displays."""
        return self._submit(self._status()).then(callback)

    @property
    def associated(self) -> bool:
        return self._session_hash is not None and self._session_hash == self.db_hash

    def forget_associations(self) -> None:
        """Drop every stored connection (KeePassXC keeps its side until the
        user removes it under Database settings → Browser Integration)."""
        self._store.clear_associations()
        self._session_hash = self.associated_id = None
        self._cache = {}
        self.stateChanged.emit()

    def wait(self, job: Job, timeout_ms: int) -> bool:
        """Block up to ``timeout_ms`` for ``job``, processing KeePassXC's
        replies as they arrive. True if it finished."""
        deadline = time.monotonic() + timeout_ms / 1000
        while not job.done:
            remaining = int((deadline - time.monotonic()) * 1000)
            sock = self._socket
            if remaining <= 0 or sock is None or sock.state() != QLocalSocket.LocalSocketState.ConnectedState:
                break
            if not sock.waitForReadyRead(remaining):
                break
        return job.done

    # ------------------------------------------------------------------
    # Jobs

    def _get_logins(self, url: str) -> Steps[list[Login]]:
        yield from self._session()
        keys = [{"id": a["id"], "key": a["key"]} for a in self._store.associations().values()]
        try:
            reply = yield _Raw(
                "get-logins", {"url": url, "id": self.associated_id or "", "keys": keys}, timeout=INTERACTIVE_TIMEOUT_MS
            )
        except KeePassXCError as e:
            if e.code != NO_LOGINS_FOUND:
                raise
            logins = []
        else:
            logins = [Login.from_json(e) for e in reply.get("entries") or [] if isinstance(e, dict)]
        self._cache[site_key(url)] = (time.monotonic(), logins)
        return logins

    def _save_login(self, url: str, login: str, password: str, uuid: str | None, trigger_unlock: bool) -> Steps[str]:
        yield from self._session(trigger_unlock=trigger_unlock)
        if not uuid:
            self._cache.pop(site_key(url), None)
            for entry in (yield from self._get_logins(url)):
                if entry.login == login:
                    if entry.password == password:
                        return "unchanged"
                    uuid = entry.uuid
                    break
        yield from self._space_writes()
        reply = yield _Raw(
            "set-login",
            {
                "url": url,
                "submitUrl": url,
                "id": self.associated_id or "",
                "login": login,
                "password": password,
                "group": "",
                "groupUuid": "",
                "uuid": uuid or "",
                "downloadFavicon": "false",
            },
            timeout=INTERACTIVE_TIMEOUT_MS,
        )
        self._last_write = time.monotonic()
        self._cache = {}
        if reply.get("error") not in (None, "", "success"):
            return "declined"  # the user cancelled KeePassXC's update dialog
        return "updated" if uuid else "added"

    def _get_totp(self, uuid: str) -> Steps[str]:
        yield from self._session()
        reply = yield _Raw("get-totp", {"uuid": uuid})
        return str(reply.get("totp") or "")

    def _passkeys(self, action: str, public_key: dict[str, Any], origin: str) -> Steps[dict[str, Any]]:
        yield from self._session(trigger_unlock=True)
        keys = [{"id": a["id"], "key": a["key"]} for a in self._store.associations().values()]
        message = {"publicKey": public_key, "origin": origin, "keys": keys}
        if action == "passkeys-register":
            message["groupName"] = ""  # KeePassXC's default passkeys group
            yield from self._space_writes()
        reply = yield _Raw(action, message, timeout=INTERACTIVE_TIMEOUT_MS)
        if action == "passkeys-register":
            self._last_write = time.monotonic()
        response = reply.get("response")
        if not isinstance(response, dict):
            raise KeePassXCError(PROTOCOL_ERROR, "KeePassXC sent no passkey response")
        return response

    def _associate(self) -> Steps[str]:
        self._associate_after_unlock = True
        try:
            db_hash = yield from self._session(interactive=True, trigger_unlock=True)
        except KeePassXCError as e:
            if e.code != DATABASE_NOT_OPENED:
                self._associate_after_unlock = False
            raise
        self._associate_after_unlock = False
        return db_hash

    def _unlock(self) -> Steps[bool]:
        self._connect()
        yield from self._keys()
        if self.db_hash is None:
            try:
                reply = yield _Raw("get-databasehash", trigger_unlock=True)
            except KeePassXCError as e:
                if e.code != DATABASE_NOT_OPENED:
                    raise
                self._note_error(e)
                return False  # KeePassXC is showing its unlock dialog
            self._set_hash(reply.get("hash"))
        return True

    def _status(self) -> Steps[dict[str, Any]]:
        try:
            yield from self._session()
        except KeePassXCError as e:
            if e.code not in (NOT_RUNNING, DATABASE_NOT_OPENED, NOT_ASSOCIATED):
                raise
        return {
            "running": bool(self.running),
            "locked": self.locked,
            "hash": self.db_hash,
            "associated": self.associated,
            "id": self.associated_id,
        }

    # --- session prerequisites ----------------------------------------

    def _session(self, interactive: bool = False, trigger_unlock: bool = False) -> Steps[str]:
        """Connected, keys exchanged, open database known and associated.
        Returns the database hash."""
        self._connect()
        public_key = yield from self._keys()
        # Kept locally: a lock/unlock broadcast can reset self.db_hash while we wait.
        db_hash = self.db_hash
        if db_hash is None:
            reply = yield _Raw("get-databasehash", trigger_unlock=trigger_unlock)
            db_hash = self._set_hash(reply.get("hash"))
        if self._session_hash == db_hash:
            return db_hash

        assoc = self._store.association(db_hash)
        if assoc:
            try:
                yield _Raw("test-associate", {"id": assoc["id"], "key": assoc["key"]})
            except KeePassXCError as e:
                if e.code != ASSOCIATION_FAILED:
                    raise
                log.info("KeePassXC no longer knows connection %r; forgetting it", assoc["id"])
                self._store.remove_association(db_hash)
            else:
                self._set_associated(db_hash, assoc["id"])
                return db_hash

        if not interactive:
            self.associated_id = None
            raise KeePassXCError(NOT_ASSOCIATED, "The open KeePassXC database isn't connected to Falkon")
        id_public, _ = sodium.keypair()
        reply = yield _Raw(
            "associate", {"key": _b64(public_key), "idKey": _b64(id_public)}, timeout=INTERACTIVE_TIMEOUT_MS
        )
        db_hash = self._set_hash(reply.get("hash") or db_hash)
        assoc_id = str(reply["id"])
        self._store.set_association(db_hash, assoc_id, _b64(id_public))
        self._set_associated(db_hash, assoc_id)
        return db_hash

    def _space_writes(self) -> Steps[None]:
        """Wait until KeePassXC has had time to save our previous change."""
        if self._last_write is not None:
            remaining = WRITE_SPACING_S - (time.monotonic() - self._last_write)
            if remaining > 0:
                log.debug("waiting %.1f s for KeePassXC to save the previous change", remaining)
                yield _Sleep(remaining)

    def _keys(self) -> Steps[bytes]:
        """This session's keys, exchanging them first if needed; returns our public key."""
        if self._crypto is not None:
            return self._crypto[1]
        public, secret = sodium.keypair()
        reply = yield _Raw("change-public-keys", plain={"publicKey": _b64(public)})
        self._crypto = (sodium.Box(secret, _unb64(reply["publicKey"])), public)
        return public

    def _set_hash(self, db_hash: object) -> str:
        if not isinstance(db_hash, str) or not db_hash:
            raise KeePassXCError(PROTOCOL_ERROR, "KeePassXC sent no database hash")
        if db_hash != self.db_hash or self.locked is not False:
            self.db_hash, self.locked = db_hash, False
            self.stateChanged.emit()
        return db_hash

    def _set_associated(self, db_hash: str, assoc_id: str) -> None:
        changed = self._session_hash != db_hash or self.associated_id != assoc_id
        self._session_hash, self.associated_id = db_hash, assoc_id
        if changed:
            self.stateChanged.emit()

    # ------------------------------------------------------------------
    # Job scheduling

    def _submit(self, gen: Steps[Any]) -> Job:
        job = Job(gen)
        self._jobs.append(job)
        self._pump()
        return job

    def _pump(self) -> None:
        if self._pumping:
            return
        self._pumping = True
        try:
            while self._current is None and self._jobs:
                self._current = self._jobs.popleft()
                self._step(self._current, None, None)
        finally:
            self._pumping = False

    def _step(self, job: Job, value: Any, error: KeePassXCError | None) -> None:
        assert job._gen is not None, "only submitted jobs have steps"
        try:
            raw = job._gen.throw(error) if error is not None else job._gen.send(value)
        except StopIteration as stop:
            self._finish(job, result=stop.value)
        except KeePassXCError as e:
            self._finish(job, error=e)
        except Exception as e:
            log.exception("KeePassXC request failed")
            self._finish(job, error=KeePassXCError(PROTOCOL_ERROR, str(e)))
        else:
            if isinstance(raw, _Sleep):
                QTimer.singleShot(int(raw.seconds * 1000), lambda: self._resume(job))
                return
            try:
                self._send(raw)
            except KeePassXCError as e:
                self._step(job, None, e)

    def _resume(self, job: Job) -> None:
        if self._current is job and not job.done:
            self._step(job, None, None)

    def _finish(self, job: Job, result: Any = None, error: KeePassXCError | None = None) -> None:
        job.done, job.result, job.error = True, result, error
        if error is not None:
            self._note_error(error)
            log.debug("KeePassXC job failed: %s (%s)", error, error.code)
        callbacks, job._callbacks = job._callbacks, []
        for cb in callbacks:
            QTimer.singleShot(0, lambda cb=cb: cb(job))
        if self._current is job:
            self._current = None
            self._pump()

    def _note_error(self, error: KeePassXCError) -> None:
        if error.code == DATABASE_NOT_OPENED and self.locked is not True:
            self.locked, self.db_hash, self._session_hash = True, None, None
            self.stateChanged.emit()
        elif error.code == NOT_RUNNING and self.running is not False:
            self.running = False
            self.stateChanged.emit()

    # ------------------------------------------------------------------
    # Wire

    def _connect(self) -> None:
        sock = self._socket
        if sock is not None and sock.state() == QLocalSocket.LocalSocketState.ConnectedState:
            return
        self._drop_socket()
        for path in self._paths():
            if not os.path.exists(path):
                continue
            sock = QLocalSocket(self)
            sock.connectToServer(path)
            if sock.waitForConnected(1000):
                sock.readyRead.connect(self._on_ready_read)
                sock.disconnected.connect(self._on_disconnected)
                self._socket = sock
                if self.running is not True:
                    self.running = True
                    self.stateChanged.emit()
                return
            sock.abort()
            sock.deleteLater()
        raise KeePassXCError(NOT_RUNNING, "KeePassXC isn't running, or its browser integration is off")

    def _send(self, raw: _Raw) -> None:
        sock = self._socket
        if sock is None or sock.state() != QLocalSocket.LocalSocketState.ConnectedState:
            raise KeePassXCError(DISCONNECTED, "Lost the connection to KeePassXC")
        nonce = os.urandom(sodium.NONCEBYTES)
        if raw.plain is not None:
            envelope = {"action": raw.action, **raw.plain, "nonce": _b64(nonce)}
        else:
            # Gone if the connection dropped while the job was paused (_Sleep).
            if self._crypto is None:
                raise KeePassXCError(DISCONNECTED, "Lost the connection to KeePassXC")
            inner = json.dumps({"action": raw.action, **raw.message}).encode("utf-8")
            envelope = {
                "action": raw.action,
                "message": _b64(self._crypto[0].encrypt(inner, nonce)),
                "nonce": _b64(nonce),
            }
            if raw.trigger_unlock:
                envelope["triggerUnlock"] = "true"
        envelope["clientID"] = self._client_id
        raw.expected_nonce = _b64(sodium.increment_nonce(nonce))
        self._inflight = raw
        sock.write(json.dumps(envelope, separators=(",", ":")).encode("utf-8"))
        sock.flush()
        self._timer.start(raw.timeout)

    def _on_ready_read(self) -> None:
        sock = self.sender()
        if sock is None or sock is not self._socket:
            return
        self._buffer += bytes(sock.readAll().data())
        if len(self._buffer) > MAX_BUFFER:
            log.warning("KeePassXC sent an oversized message; reconnecting")
            self._fail_connection(KeePassXCError(PROTOCOL_ERROR, "Oversized message from KeePassXC"))
            return
        decoder = json.JSONDecoder()
        while self._buffer.strip():
            try:
                text = self._buffer.decode("utf-8")
                start = len(text) - len(text.lstrip())
                message, end = decoder.raw_decode(text, start)
            except ValueError:
                break  # partial message: wait for the rest
            self._buffer = text[end:].encode("utf-8")
            if isinstance(message, dict):
                self._handle(message)
        if not self._buffer.strip():
            self._buffer = b""

    def _handle(self, message: dict[str, Any]) -> None:
        action = message.get("action")
        if action == "database-locked":
            self._on_database_locked()
            return
        if action == "database-unlocked":
            self._on_database_unlocked()
            return
        raw, job = self._inflight, self._current
        if raw is None or job is None or action != raw.action:
            log.debug("ignoring unexpected KeePassXC message %r", action)
            return
        self._inflight = None
        self._timer.stop()
        try:
            reply = self._open(raw, message)
        except KeePassXCError as e:
            self._step(job, None, e)
        else:
            self._step(job, reply, None)

    def _open(self, raw: _Raw, message: dict[str, Any]) -> dict[str, Any]:
        if "errorCode" in message:
            try:
                code = int(message["errorCode"])
            except (TypeError, ValueError):
                code = PROTOCOL_ERROR
            raise KeePassXCError(code, str(message.get("error") or "KeePassXC error"))
        if message.get("nonce") != raw.expected_nonce:
            raise KeePassXCError(PROTOCOL_ERROR, "KeePassXC reply has the wrong nonce")
        if raw.plain is not None:
            if message.get("success") != "true" or not message.get("publicKey"):
                raise KeePassXCError(PROTOCOL_ERROR, "KeePassXC refused the key exchange")
            return message
        if self._crypto is None:
            raise KeePassXCError(DISCONNECTED, "Lost the connection to KeePassXC")
        try:
            plaintext = self._crypto[0].decrypt(_unb64(message["message"]), _unb64(message["nonce"]))
            reply = json.loads(plaintext)
        except (KeyError, ValueError, sodium.CryptoError) as e:
            raise KeePassXCError(PROTOCOL_ERROR, f"Undecryptable reply from KeePassXC: {e}") from None
        if not isinstance(reply, dict) or reply.get("nonce") != raw.expected_nonce:
            raise KeePassXCError(PROTOCOL_ERROR, "KeePassXC reply has the wrong nonce")
        if reply.get("success") != "true":
            raise KeePassXCError(PROTOCOL_ERROR, "KeePassXC reported failure")
        return reply

    def _on_timeout(self) -> None:
        log.warning(
            "KeePassXC didn't answer %r in time; reconnecting", self._inflight.action if self._inflight else None
        )
        self._fail_connection(KeePassXCError(TIMEOUT, "KeePassXC didn't answer"))

    def _on_disconnected(self) -> None:
        if self._socket is not None and self.sender() is self._socket:
            self._fail_connection(KeePassXCError(DISCONNECTED, "KeePassXC closed the connection"))

    def _fail_connection(self, error: KeePassXCError) -> None:
        """Drop the socket (a late reply would desynchronize us) and fail the
        request in flight; queued jobs reconnect on their own."""
        had_request = self._inflight is not None
        self._drop_socket()
        if self.running is not False:
            self.running = False
            self.stateChanged.emit()
        if had_request and self._current is not None:
            self._step(self._current, None, error)

    def _drop_socket(self) -> None:
        sock, self._socket = self._socket, None
        self._inflight = None
        self._timer.stop()
        self._buffer = b""
        self._crypto = None
        self._session_hash = None
        self.db_hash = None
        self._cache = {}
        if sock is not None:
            sock.abort()
            sock.deleteLater()

    def _on_database_locked(self) -> None:
        log.debug("KeePassXC: database locked")
        self.locked, self.db_hash, self._session_hash = True, None, None
        self._cache = {}
        self.stateChanged.emit()
        # Reactions (refilling pages, retrying saves) run from the event loop,
        # not inside whatever synchronous Falkon call is pumping the socket.
        QTimer.singleShot(0, self.databaseLocked.emit)

    def _on_database_unlocked(self) -> None:
        # Possibly a different database (KeePassXC also says this when the
        # active database tab changes): re-learn its hash before trusting it.
        log.debug("KeePassXC: database unlocked")
        self.locked, self.db_hash, self._session_hash = False, None, None
        self._cache = {}
        self.stateChanged.emit()
        QTimer.singleShot(0, self.databaseUnlocked.emit)
        if self._associate_after_unlock:
            QTimer.singleShot(0, self.associate)
