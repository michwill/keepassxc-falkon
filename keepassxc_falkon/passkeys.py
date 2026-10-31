"""Passkeys (WebAuthn) served by KeePassXC.

``passkeys.js`` stands in for navigator.credentials in the page and relays
requests through ``fill.js``; they arrive here with the reporting document's
token. What a page (or another frame) says is never trusted:

- the requesting frame is found by probing frames at the reported URL for
  the token *and* the pending request id, both of which live only in that
  document's isolated world;
- the origin sent to KeePassXC is the one Chromium reports for that frame
  (KeePassXC then checks the relying-party ID against it and asks the user);
- frames on another origin than their page are refused, because KeePassXC
  signs client data with ``"crossOrigin": false``.

A locked database is unlocked (KeePassXC asks) and an unconnected one is
connected, and the request is retried once, while the page keeps waiting.
"""

import json
import logging
from collections.abc import Callable
from typing import Any

from PySide6.QtCore import QObject, QTimer, QUrl
from PySide6.QtWebEngineCore import QWebEngineFrame
from PySide6.QtWebEngineWidgets import QWebEngineView

from . import protocol
from .filler import SAFE_WORLD, frames_at, web_views
from .protocol import Job, KeePassXCClient
from .urls import is_web, origin, page_key
from .webauthn import attested_auth_data, b64url, unb64url

log = logging.getLogger("keepassxc_falkon")

DEFAULT_TIMEOUT_MS = 5 * 60 * 1000

# KeePassXC's passkey error codes (BrowserMessageBuilder.h) → DOMException.
# WebAuthn reports most failures as NotAllowedError so sites can't probe for
# credentials; we follow that, but say what happened in the message.
_ERRORS = {
    15: ("NotAllowedError", "KeePassXC has no passkey for this site."),
    21: ("InvalidStateError", "KeePassXC already has a passkey for this account."),
    22: ("NotAllowedError", "The passkey request was cancelled in KeePassXC."),
    25: ("SecurityError", "KeePassXC only uses passkeys on https:// sites."),
    26: ("SecurityError", "KeePassXC refused this origin."),
    27: ("SecurityError", "This site's domain isn't valid for passkeys."),
    28: ("SecurityError", "The relying-party ID doesn't match this site."),
    29: ("NotSupportedError", "KeePassXC supports none of the requested key algorithms."),
    32: ("TypeError", "The passkey challenge is too short."),
    33: ("TypeError", "The passkey user ID is invalid."),
}
_NOT_ALLOWED = ("NotAllowedError", "The operation either timed out or was not allowed.")


Answer = dict[str, Any]       # {"credential": {...}} or {"error": {"name", "message"}}
Deliver = Callable[[Answer], None]


def error_for(code: int) -> Answer:
    name, message = _ERRORS.get(code, _NOT_ALLOWED)
    return _error(name, message)


def _error(name: str, message: str) -> Answer:
    return {"error": {"name": name, "message": message}}


def with_attested_auth_data(credential: dict[str, Any]) -> dict[str, Any]:
    """For a new passkey, KeePassXC's separate ``authenticatorData`` lacks the
    attested credential data; ``getAuthenticatorData()`` must return the copy
    inside ``attestationObject`` (WebAuthn, AuthenticatorAttestationResponse)."""
    response = credential.get("response")
    if not isinstance(response, dict):
        log.warning("KeePassXC sent a passkey without a response")
        return credential
    try:
        response["authenticatorData"] = b64url(attested_auth_data(unb64url(response["attestationObject"])))
    except (TypeError, KeyError, ValueError, IndexError) as e:
        log.warning("couldn't read the attestation object from KeePassXC: %s", e)
    return credential


class PasskeyBroker(QObject):
    def __init__(self, client: KeePassXCClient, parent: QObject | None = None,
                 views: Callable[[], list[QWebEngineView]] = web_views) -> None:
        super().__init__(parent)
        self._client = client
        self._views = views

    def request(self, token: str, href: str, request_id: str, kind: str, options: str) -> None:
        url = QUrl(href)
        if kind not in ("create", "get") or not is_web(url) or not token or not request_id:
            return
        try:
            public_key: object = json.loads(options)
        except ValueError:
            public_key = None
        # Referenced by the probe callbacks: keeps the views (and so their
        # pages' Python wrappers) alive until the frames answer.
        views = self._views()
        candidates = frames_at(views, page_key(url))
        probe = (f"(function(){{var k=window.__kpxcFalkon;return !!(k&&k.token==={json.dumps(token)}"
                 f"&&k.hasPasskeyRequest({json.dumps(request_id)}));}})()")
        verified = False

        def answered(frame: QWebEngineFrame, view: QWebEngineView, result: object) -> None:
            nonlocal verified
            if verified or result is not True:
                return
            verified = True
            log.debug("passkey %s request %s verified in a frame at %s", kind, request_id, frame.url().toString())
            self._verified(frame, view, token, request_id, kind, public_key, views)

        log.debug("passkey %s request %s from %s: %d candidate frame(s)", kind, request_id, href, len(candidates))
        for frame, view in candidates:
            frame.runJavaScript(probe, SAFE_WORLD, lambda r, f=frame, v=view: answered(f, v, r))

    def _verified(self, frame: QWebEngineFrame, view: QWebEngineView, token: str, request_id: str, kind: str,
                  public_key: object, views: list[QWebEngineView]) -> None:
        def deliver(answer: Answer) -> None:
            log.debug("passkey request %s answered: %s", request_id,
                      answer["error"]["name"] if "error" in answer else "credential")
            script = (f"(function(){{var k=window.__kpxcFalkon;return !!(k&&k.token==={json.dumps(token)})"
                      f"&&k.passkeyResult({json.dumps(request_id)},{json.dumps(json.dumps(answer))});}})()")
            if frame.isValid():
                frame.runJavaScript(script, SAFE_WORLD)
            views.clear()

        frame_origin = origin(frame.url())
        top_origin = origin(view.page().mainFrame().url())
        if frame_origin != top_origin:
            deliver(_error("NotAllowedError", "KeePassXC passkeys work in the page itself, "
                                              "not in frames embedded from another site."))
        elif not isinstance(public_key, dict):
            deliver(_error("TypeError", "Unreadable passkey request."))
        else:
            timeout = public_key.get("timeout")
            timeout = timeout if isinstance(timeout, int) and timeout > 0 else DEFAULT_TIMEOUT_MS
            self._ask(kind, public_key, frame_origin, deliver, timeout, retried=False)

    def _ask(self, kind: str, public_key: dict[str, Any], frame_origin: str, deliver: Deliver,
             timeout: int, retried: bool) -> None:
        def answered(job: Job) -> None:
            if job.error is None:
                response: dict[str, Any] = job.result
                if "errorCode" not in response:
                    if kind == "create":
                        response = with_attested_auth_data(response)
                    deliver({"credential": response})
                    return
                code = int(response["errorCode"])
            else:
                code = job.error.code
            log.debug("KeePassXC passkey answer: error %s%s", code, " (retried)" if retried else "")
            if not retried and code == protocol.DATABASE_NOT_OPENED:
                self._after_unlock(retry, deliver, timeout)
            elif not retried and code == protocol.NOT_ASSOCIATED:
                self._client.associate(callback=lambda j: retry() if j.error is None else deliver(error_for(code)))
            elif code == protocol.NOT_RUNNING:
                deliver(_error("NotAllowedError", "KeePassXC isn't running."))
            else:
                deliver(error_for(code))

        def retry() -> None:
            self._ask(kind, public_key, frame_origin, deliver, timeout, retried=True)

        self._client.passkeys(kind, public_key, frame_origin, callback=answered)

    def _after_unlock(self, retry: Callable[[], None], deliver: Deliver, timeout: int) -> None:
        """KeePassXC is showing its unlock dialog (we asked): carry on when
        the database opens, or give up when the page's timeout runs out."""
        if self._client.locked is False:
            retry()         # unlocked already, before we got to wait
            return
        waiting = True
        log.debug("passkey request waits for the database to be unlocked")

        def unlocked() -> None:
            nonlocal waiting
            if waiting:
                waiting = False
                self._client.databaseUnlocked.disconnect(unlocked)
                retry()

        def expired() -> None:
            nonlocal waiting
            if waiting:
                waiting = False
                self._client.databaseUnlocked.disconnect(unlocked)
                deliver(error_for(protocol.DATABASE_NOT_OPENED))

        self._client.databaseUnlocked.connect(unlocked)
        QTimer.singleShot(timeout, expired)
