"""The object fill.js reaches as ``window.external.extra.keepassxc``."""

import logging
from typing import TYPE_CHECKING

from PySide6.QtCore import QObject, Slot

if TYPE_CHECKING:
    from .filler import Filler
    from .passkeys import PasskeyBroker

log = logging.getLogger("keepassxc_falkon")


class Bridge(QObject):
    def __init__(self, filler: "Filler", passkeys: "PasskeyBroker", parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._filler = filler
        self._passkeys = passkeys

    # Exceptions in web-channel slots vanish silently; log them.

    @Slot(str, str, str)
    def loginFormFound(self, token: str, href: str, info: str) -> None:
        try:
            self._filler.login_form_found(token, href, info)
        except Exception:
            log.exception("handling a login form failed")

    @Slot(str, str, str, str, str)
    def passkeyRequest(self, token: str, href: str, request_id: str, kind: str, options: str) -> None:
        try:
            self._passkeys.request(token, href, request_id, kind, options)
        except Exception:
            log.exception("handling a passkey request failed")
