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

from PySide6.QtCore import QObject, QTimer, QUrl

from . import protocol
from .filler import SAFE_WORLD, frames_at, web_views
from .urls import is_web, origin, page_key
from .webauthn import attested_auth_data, b64url, unb64url

log = logging.getLogger("keepassxc_falkon")

PROBE_TIMEOUT_MS = 3000
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


def error_for(code):
    name, message = _ERRORS.get(code, _NOT_ALLOWED)
    return {"error": {"name": name, "message": message}}


def _error(name, message):
    return {"error": {"name": name, "message": message}}


def with_attested_auth_data(credential):
    """For a new passkey, KeePassXC's separate ``authenticatorData`` lacks the
    attested credential data; ``getAuthenticatorData()`` must return the copy
    inside ``attestationObject`` (WebAuthn, AuthenticatorAttestationResponse)."""
    response = credential.get("response")
    try:
        response["authenticatorData"] = b64url(attested_auth_data(unb64url(response["attestationObject"])))
    except (TypeError, KeyError, ValueError, IndexError) as e:
        log.warning("couldn't read the attestation object from KeePassXC: %s", e)
    return credential


class PasskeyBroker(QObject):
    def __init__(self, client, parent=None, views=web_views):
        super().__init__(parent)
        self._client = client
        self._views = views

    def request(self, token, href, request_id, kind, options):
        url = QUrl(href)
        if kind not in ("create", "get") or not is_web(url) or not token or not request_id:
            return
        try:
            public_key = json.loads(options)
        except ValueError:
            public_key = None
        state = {"views": self._views(), "left": 0, "done": False}
        candidates = frames_at(state["views"], page_key(url))
        probe = ("(function(){var k=window.__kpxcFalkon;return !!(k&&k.token===%s&&k.hasPasskeyRequest(%s));})()"
                 % (json.dumps(token), json.dumps(request_id)))

        def answered(frame, view, result):
            state["left"] -= 1
            if state["done"] or result is not True:
                return
            state["done"] = True
            log.debug("passkey %s request %s verified in a frame at %s", kind, request_id, frame.url().toString())
            self._verified(frame, view, token, request_id, kind, public_key, state["views"])

        log.debug("passkey %s request %s from %s: %d candidate frame(s)", kind, request_id, href, len(candidates))
        for frame, view in candidates:
            frame.runJavaScript(probe, SAFE_WORLD, lambda r, f=frame, v=view: answered(f, v, r))
            state["left"] += 1
        # A frame torn down mid-probe never answers; nothing to clean up but
        # the views we hold.
        QTimer.singleShot(PROBE_TIMEOUT_MS, lambda: state.update(views=[]) if not state["done"] else None)

    def _verified(self, frame, view, token, request_id, kind, public_key, views):
        def deliver(result):
            log.debug("passkey request %s answered: %s", request_id,
                      result["error"]["name"] if "error" in result else "credential")
            script = ("(function(){var k=window.__kpxcFalkon;return !!(k&&k.token===%s)&&k.passkeyResult(%s,%s);})()"
                      % (json.dumps(token), json.dumps(request_id), json.dumps(json.dumps(result))))
            if frame.isValid():
                frame.runJavaScript(script, SAFE_WORLD)
            views.clear()

        frame_origin = origin(frame.url())
        top_origin = origin(view.page().mainFrame().url())
        if frame_origin != top_origin:
            return deliver(_error("NotAllowedError", "KeePassXC passkeys work in the page itself, "
                                                     "not in frames embedded from another site."))
        if not isinstance(public_key, dict):
            return deliver(_error("TypeError", "Unreadable passkey request."))
        timeout = public_key.get("timeout")
        timeout = timeout if isinstance(timeout, int) and timeout > 0 else DEFAULT_TIMEOUT_MS
        self._ask(kind, public_key, frame_origin, deliver, timeout, retried=False)

    def _ask(self, kind, public_key, frame_origin, deliver, timeout, retried):
        def answered(job):
            if job.error is None:
                response = job.result
                if "errorCode" not in response:
                    if kind == "create":
                        response = with_attested_auth_data(response)
                    return deliver({"credential": response})
                code = response["errorCode"]
            else:
                code = job.error.code
            log.debug("KeePassXC passkey answer: error %s%s", code, " (retried)" if retried else "")
            if not retried and code == protocol.DATABASE_NOT_OPENED:
                return self._after_unlock(retry, deliver, timeout)
            if not retried and code == protocol.NOT_ASSOCIATED:
                return self._client.associate(
                    callback=lambda j: retry() if j.error is None else deliver(error_for(code)))
            if code == protocol.NOT_RUNNING:
                return deliver(_error("NotAllowedError", "KeePassXC isn't running."))
            deliver(error_for(code))

        def retry():
            self._ask(kind, public_key, frame_origin, deliver, timeout, retried=True)

        self._client.passkeys(kind, public_key, frame_origin, callback=answered)

    def _after_unlock(self, retry, deliver, timeout):
        """KeePassXC is showing its unlock dialog (we asked): carry on when
        the database opens, or give up when the page's timeout runs out."""
        if self._client.locked is False:
            return retry()      # unlocked already, before we got to wait
        waiting = {"live": True}
        log.debug("passkey request waits for the database to be unlocked")

        def unlocked():
            if waiting["live"]:
                waiting["live"] = False
                self._client.databaseUnlocked.disconnect(unlocked)
                retry()

        def expired():
            if waiting["live"]:
                waiting["live"] = False
                self._client.databaseUnlocked.disconnect(unlocked)
                deliver(error_for(protocol.DATABASE_NOT_OPENED))

        self._client.databaseUnlocked.connect(unlocked)
        QTimer.singleShot(timeout, expired)
