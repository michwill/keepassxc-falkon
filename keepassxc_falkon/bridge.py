"""The object fill.js reaches as ``window.external.extra.keepassxc``."""

import logging

from PySide6.QtCore import QObject, Slot

log = logging.getLogger("keepassxc_falkon")


class Bridge(QObject):
    def __init__(self, filler, passkeys, parent=None):
        super().__init__(parent)
        self._filler = filler
        self._passkeys = passkeys

    # Exceptions in web-channel slots vanish silently; log them.

    @Slot(str, str, str)
    def loginFormFound(self, token, href, info):
        try:
            self._filler.login_form_found(token, href, info)
        except Exception:
            log.exception("handling a login form failed")

    @Slot(str, str, str, str, str)
    def passkeyRequest(self, token, href, request_id, kind, options):
        try:
            self._passkeys.request(token, href, request_id, kind, options)
        except Exception:
            log.exception("handling a passkey request failed")
