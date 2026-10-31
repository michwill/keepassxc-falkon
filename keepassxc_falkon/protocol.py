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
from dataclasses import dataclass

from PySide6.QtCore import QDir, QObject, QStandardPaths, QTimer, Signal
from PySide6.QtNetwork import QLocalSocket

from . import sodium

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
CACHE_TTL_S = 30
MAX_BUFFER = 8 * 1024 * 1024


class KeePassXCError(Exception):
    def __init__(self, code, message):
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
    def from_json(cls, obj):
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


def socket_paths():
    """Where KeePassXC may be listening (src/browser/BrowserShared.cpp)."""
    runtime = os.environ.get("XDG_RUNTIME_DIR") or QStandardPaths.writableLocation(
        QStandardPaths.StandardLocation.RuntimeLocation)
    paths = [
        os.path.join(runtime, "app", "org.keepassxc.KeePassXC", SERVER_NAME),
        os.path.join(runtime, SERVER_NAME),  # legacy symlink (non-Flatpak)
    ]
    snap = os.path.expanduser(os.path.join("~", "snap", "keepassxc", "common", SERVER_NAME))
    paths += [snap, os.path.join(QDir.tempPath(), SERVER_NAME)]
    return paths


def _b64(data):
    return base64.b64encode(data).decode("ascii")


def _unb64(text):
    return base64.b64decode(text, validate=True)


class _Raw:
    """One request on the wire. ``plain`` marks the unencrypted key exchange."""

    def __init__(self, action, message=None, *, plain=None, nonce=None,
                 trigger_unlock=False, timeout=QUICK_TIMEOUT_MS):
        self.action = action
        self.message = message or {}
        self.plain = plain
        self.nonce = nonce
        self.trigger_unlock = trigger_unlock
        self.timeout = timeout
        self.expected_nonce = None


class Job:
    """A running operation. ``result``/``error`` are set when ``done``."""

    def __init__(self, gen=None):
        self._gen = gen
        self.done = False
        self.result = None
        self.error = None
        self._callbacks = []

    def then(self, callback):
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
    def finished(cls, result=None, error=None):
        job = cls()
        job.done, job.result, job.error = True, result, error
        return job


class KeePassXCClient(QObject):
    # Anything user-visible changed: reachability, lock state, association.
    stateChanged = Signal()
    databaseUnlocked = Signal()
    databaseLocked = Signal()

    def __init__(self, store, parent=None, paths=socket_paths):
        super().__init__(parent)
        self._store = store
        self._paths = paths
        self._client_id = _b64(os.urandom(24))
        self._socket = None
        self._buffer = b""
        self._jobs = deque()
        self._current = None
        self._inflight = None
        self._pumping = False
        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.timeout.connect(self._on_timeout)
        self._cache = {}          # url -> (monotonic time, [Login])
        self._pending = {}        # url -> Job (get-logins in progress)
        self._associate_after_unlock = False
        # Session state, reset whenever the connection drops.
        self._box = None
        self._public_key = None
        self._session_hash = None  # database test-associated this session
        # What we last learned, for status displays.
        self.running = None
        self.locked = None
        self.db_hash = None
        self.associated_id = None

    # ------------------------------------------------------------------
    # Public API — every call returns a Job; pass ``callback(job)`` or
    # block on it with ``wait()``.

    def get_logins(self, url, callback=None):
        """The entries KeePassXC offers for ``url`` (empty if none).
        Answers from a short-lived cache; concurrent asks share one request."""
        hit = self._cache.get(url)
        if hit is not None and time.monotonic() - hit[0] < CACHE_TTL_S:
            return Job.finished(result=hit[1]).then(callback)
        job = self._pending.get(url)
        if job is None or job.done:
            job = self._submit(self._get_logins(url))
            self._pending[url] = job
            job.then(lambda _j: self._pending.pop(url, None))
        return job.then(callback)

    def cached_logins(self, url):
        hit = self._cache.get(url)
        return hit[1] if hit is not None else None

    def save_login(self, url, login, password, uuid=None, *, trigger_unlock=False, callback=None):
        """Create or update an entry. Without ``uuid``, an existing entry
        with the same username is updated rather than duplicated. Result:
        ``"added"``, ``"updated"``, ``"unchanged"`` or ``"declined"``."""
        return self._submit(self._save_login(url, login, password, uuid, trigger_unlock)).then(callback)

    def get_totp(self, uuid, callback=None):
        """The entry's current TOTP code (empty if it has none)."""
        return self._submit(self._get_totp(uuid)).then(callback)

    def associate(self, callback=None):
        """Connect to the open database (KeePassXC asks the user to name the
        connection). Asks KeePassXC to unlock first if needed, and retries
        once the database is unlocked."""
        return self._submit(self._associate()).then(callback)

    def unlock(self, callback=None):
        """Ask KeePassXC to show its unlock dialog (no-op if unlocked)."""
        return self._submit(self._unlock()).then(callback)

    def status(self, callback=None):
        """Probe without prompting: result is a dict for status displays."""
        return self._submit(self._status()).then(callback)

    @property
    def associated(self):
        return self._session_hash is not None and self._session_hash == self.db_hash

    def forget_associations(self):
        """Drop every stored connection (KeePassXC keeps its side until the
        user removes it under Database settings → Browser Integration)."""
        self._store.clear_associations()
        self._session_hash = self.associated_id = None
        self._cache = {}
        self.stateChanged.emit()

    def wait(self, job, timeout_ms):
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

    def _get_logins(self, url):
        yield from self._session()
        keys = [{"id": a["id"], "key": a["key"]} for a in self._store.associations().values()]
        try:
            reply = yield _Raw("get-logins", {"url": url, "id": self.associated_id or "", "keys": keys},
                               timeout=INTERACTIVE_TIMEOUT_MS)
        except KeePassXCError as e:
            if e.code != NO_LOGINS_FOUND:
                raise
            logins = []
        else:
            logins = [Login.from_json(e) for e in reply.get("entries") or [] if isinstance(e, dict)]
        self._cache[url] = (time.monotonic(), logins)
        return logins

    def _save_login(self, url, login, password, uuid, trigger_unlock):
        yield from self._session(trigger_unlock=trigger_unlock)
        if not uuid:
            self._cache.pop(url, None)
            for entry in (yield from self._get_logins(url)):
                if entry.login == login:
                    if entry.password == password:
                        return "unchanged"
                    uuid = entry.uuid
                    break
        reply = yield _Raw("set-login", {
            "url": url,
            "submitUrl": url,
            "id": self.associated_id or "",
            "login": login,
            "password": password,
            "group": "",
            "groupUuid": "",
            "uuid": uuid or "",
            "downloadFavicon": "false",
        }, timeout=INTERACTIVE_TIMEOUT_MS)
        self._cache = {}
        if reply.get("error") not in (None, "", "success"):
            return "declined"   # the user cancelled KeePassXC's update dialog
        return "updated" if uuid else "added"

    def _get_totp(self, uuid):
        yield from self._session()
        reply = yield _Raw("get-totp", {"uuid": uuid})
        return str(reply.get("totp") or "")

    def _associate(self):
        self._associate_after_unlock = True
        try:
            db_hash = yield from self._session(interactive=True, trigger_unlock=True)
        except KeePassXCError as e:
            if e.code != DATABASE_NOT_OPENED:
                self._associate_after_unlock = False
            raise
        self._associate_after_unlock = False
        return db_hash

    def _unlock(self):
        self._connect()
        yield from self._keys()
        if self.db_hash is None:
            try:
                reply = yield _Raw("get-databasehash", trigger_unlock=True)
            except KeePassXCError as e:
                if e.code != DATABASE_NOT_OPENED:
                    raise
                self._note_error(e)
                return False      # KeePassXC is showing its unlock dialog
            self._set_hash(reply.get("hash"))
        return True

    def _status(self):
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

    def _session(self, interactive=False, trigger_unlock=False):
        """Connected, keys exchanged, open database known and associated.
        Returns the database hash."""
        self._connect()
        yield from self._keys()
        if self.db_hash is None:
            reply = yield _Raw("get-databasehash", trigger_unlock=trigger_unlock)
            self._set_hash(reply.get("hash"))
        # A lock/unlock broadcast can reset self.db_hash while we wait below.
        db_hash = self.db_hash
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
        reply = yield _Raw("associate", {"key": _b64(self._public_key), "idKey": _b64(id_public)},
                           timeout=INTERACTIVE_TIMEOUT_MS)
        db_hash = reply.get("hash") or db_hash
        self._store.set_association(db_hash, reply["id"], _b64(id_public))
        self._set_hash(db_hash)
        self._set_associated(db_hash, reply["id"])
        return db_hash

    def _keys(self):
        if self._box is not None:
            return
        public, secret = sodium.keypair()
        nonce = os.urandom(sodium.NONCEBYTES)
        reply = yield _Raw("change-public-keys", plain={"publicKey": _b64(public), "nonce": _b64(nonce)},
                           nonce=nonce)
        self._box = sodium.Box(secret, _unb64(reply["publicKey"]))
        self._public_key = public

    def _set_hash(self, db_hash):
        if not db_hash:
            raise KeePassXCError(PROTOCOL_ERROR, "KeePassXC sent no database hash")
        if db_hash != self.db_hash or self.locked is not False:
            self.db_hash, self.locked = db_hash, False
            self.stateChanged.emit()

    def _set_associated(self, db_hash, assoc_id):
        changed = self._session_hash != db_hash or self.associated_id != assoc_id
        self._session_hash, self.associated_id = db_hash, assoc_id
        if changed:
            self.stateChanged.emit()

    # ------------------------------------------------------------------
    # Job scheduling

    def _submit(self, gen):
        job = Job(gen)
        self._jobs.append(job)
        self._pump()
        return job

    def _pump(self):
        if self._pumping:
            return
        self._pumping = True
        try:
            while self._current is None and self._jobs:
                self._current = self._jobs.popleft()
                self._step(None, None)
        finally:
            self._pumping = False

    def _step(self, value, error):
        job = self._current
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
            try:
                self._send(raw)
            except KeePassXCError as e:
                self._step(None, e)

    def _finish(self, job, result=None, error=None):
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

    def _note_error(self, error):
        if error.code == DATABASE_NOT_OPENED and self.locked is not True:
            self.locked, self.db_hash, self._session_hash = True, None, None
            self.stateChanged.emit()
        elif error.code == NOT_RUNNING and self.running is not False:
            self.running = False
            self.stateChanged.emit()

    # ------------------------------------------------------------------
    # Wire

    def _connect(self):
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

    def _send(self, raw):
        sock = self._socket
        if sock is None or sock.state() != QLocalSocket.LocalSocketState.ConnectedState:
            raise KeePassXCError(DISCONNECTED, "Lost the connection to KeePassXC")
        if raw.plain is not None:
            envelope = {"action": raw.action, **raw.plain}
            nonce = raw.nonce
        else:
            nonce = os.urandom(sodium.NONCEBYTES)
            inner = json.dumps({"action": raw.action, **raw.message}).encode("utf-8")
            envelope = {"action": raw.action, "message": _b64(self._box.encrypt(inner, nonce)),
                        "nonce": _b64(nonce)}
            if raw.trigger_unlock:
                envelope["triggerUnlock"] = "true"
        envelope["clientID"] = self._client_id
        raw.expected_nonce = _b64(sodium.increment_nonce(nonce))
        self._inflight = raw
        sock.write(json.dumps(envelope, separators=(",", ":")).encode("utf-8"))
        sock.flush()
        self._timer.start(raw.timeout)

    def _on_ready_read(self):
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
                break       # partial message: wait for the rest
            self._buffer = text[end:].encode("utf-8")
            if isinstance(message, dict):
                self._handle(message)
        if not self._buffer.strip():
            self._buffer = b""

    def _handle(self, message):
        action = message.get("action")
        if action == "database-locked":
            self._on_database_locked()
            return
        if action == "database-unlocked":
            self._on_database_unlocked()
            return
        raw = self._inflight
        if raw is None or action != raw.action:
            log.debug("ignoring unexpected KeePassXC message %r", action)
            return
        self._inflight = None
        self._timer.stop()
        try:
            reply = self._open(raw, message)
        except KeePassXCError as e:
            self._step(None, e)
        else:
            self._step(reply, None)

    def _open(self, raw, message):
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
        try:
            plaintext = self._box.decrypt(_unb64(message["message"]), _unb64(message["nonce"]))
            reply = json.loads(plaintext)
        except (KeyError, ValueError, sodium.CryptoError) as e:
            raise KeePassXCError(PROTOCOL_ERROR, f"Undecryptable reply from KeePassXC: {e}") from None
        if not isinstance(reply, dict) or reply.get("nonce") != raw.expected_nonce:
            raise KeePassXCError(PROTOCOL_ERROR, "KeePassXC reply has the wrong nonce")
        if reply.get("success") != "true":
            raise KeePassXCError(PROTOCOL_ERROR, "KeePassXC reported failure")
        return reply

    def _on_timeout(self):
        log.warning("KeePassXC didn't answer %r in time; reconnecting",
                    self._inflight.action if self._inflight else None)
        self._fail_connection(KeePassXCError(TIMEOUT, "KeePassXC didn't answer"))

    def _on_disconnected(self):
        if self._socket is not None and self.sender() is self._socket:
            self._fail_connection(KeePassXCError(DISCONNECTED, "KeePassXC closed the connection"))

    def _fail_connection(self, error):
        """Drop the socket (a late reply would desynchronize us) and fail the
        request in flight; queued jobs reconnect on their own."""
        had_request = self._inflight is not None
        self._drop_socket()
        if self.running is not False:
            self.running = False
            self.stateChanged.emit()
        if had_request and self._current is not None:
            self._step(None, error)

    def _drop_socket(self):
        sock, self._socket = self._socket, None
        self._inflight = None
        self._timer.stop()
        self._buffer = b""
        self._box = self._public_key = self._session_hash = None
        self.db_hash = None
        self._cache = {}
        if sock is not None:
            sock.abort()
            sock.deleteLater()

    def _on_database_locked(self):
        self.locked, self.db_hash, self._session_hash = True, None, None
        self._cache = {}
        self.stateChanged.emit()
        # Reactions (refilling pages, retrying saves) run from the event loop,
        # not inside whatever synchronous Falkon call is pumping the socket.
        QTimer.singleShot(0, self.databaseLocked.emit)

    def _on_database_unlocked(self):
        # Possibly a different database (KeePassXC also says this when the
        # active database tab changes): re-learn its hash before trusting it.
        self.locked, self.db_hash, self._session_hash = False, None, None
        self._cache = {}
        self.stateChanged.emit()
        QTimer.singleShot(0, self.databaseUnlocked.emit)
        if self._associate_after_unlock:
            QTimer.singleShot(0, self.associate)
