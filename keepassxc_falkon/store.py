"""Persistent plugin state: KeePassXC associations and a few options.

An association is what KeePassXC hands back when the user approves the
"new key association request" dialog: the connection name (``id``) and
the identification public key we sent (``key``), stored under the
database's hash. Anyone holding the pair can query that database (still
subject to KeePassXC's per-site confirmation), so the file is written
owner-only, like the browser-extension storage keepassxc-browser uses.
"""

import json
import logging
import os
import tempfile
from typing import Any

log = logging.getLogger("keepassxc_falkon")

DEFAULT_OPTIONS: dict[str, Any] = {
    # Ask KeePassXC to show its unlock dialog when a page has a login
    # form and the database is locked.
    "unlock_on_login_form": True,
    # With several matching entries, fill the best match on page load
    # (Falkon's own behaviour) instead of waiting for the user to pick.
    "fill_first_of_many": False,
    # Answer websites' passkey (WebAuthn) requests with KeePassXC.
    "passkeys": True,
    # Copied passwords / TOTP codes are wiped from the clipboard after this
    # many seconds (0: never), if nothing else was copied meanwhile.
    "clipboard_clear_seconds": 10,
    # Fills the login form in the current tab (Qt portable text; "" = off).
    "fill_shortcut": "Ctrl+Shift+U",
    # Our toolbar button has been put on the navigation bar once; after that
    # the layout is the user's (Configure Toolbar).
    "toolbar_button_placed": False,
}


class Store:
    def __init__(self, path: str) -> None:
        self.path = path
        self._data: dict[str, dict[str, Any]] = {"associations": {}, "options": {}}
        self._load()

    def _load(self) -> None:
        try:
            with open(self.path, encoding="utf-8") as f:
                data = json.load(f)
        except FileNotFoundError:
            return
        except (OSError, ValueError) as e:
            log.warning("ignoring unreadable %s: %s", self.path, e)
            return
        if isinstance(data, dict):
            self._data["associations"] = dict(data.get("associations") or {})
            self._data["options"] = dict(data.get("options") or {})

    def _save(self) -> None:
        directory = os.path.dirname(self.path) or "."
        os.makedirs(directory, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=directory, prefix=".keepassxc-", suffix=".json")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(self._data, f, indent=2, sort_keys=True)
            os.chmod(tmp, 0o600)
            os.replace(tmp, self.path)
        except BaseException:
            os.unlink(tmp)
            raise

    # --- associations -------------------------------------------------

    def associations(self) -> dict[str, dict[str, str]]:
        """``{database_hash: {"id": ..., "key": ...}}``"""
        return dict(self._data["associations"])

    def association(self, db_hash: str) -> dict[str, str] | None:
        assoc: dict[str, str] | None = self._data["associations"].get(db_hash)
        return assoc

    def set_association(self, db_hash: str, assoc_id: str, key: str) -> None:
        self._data["associations"][db_hash] = {"id": assoc_id, "key": key}
        self._save()

    def remove_association(self, db_hash: str) -> None:
        if self._data["associations"].pop(db_hash, None) is not None:
            self._save()

    def clear_associations(self) -> None:
        self._data["associations"] = {}
        self._save()

    # --- options ------------------------------------------------------

    def option(self, name: str) -> Any:
        return self._data["options"].get(name, DEFAULT_OPTIONS[name])

    def set_option(self, name: str, value: Any) -> None:
        self._data["options"][name] = value
        self._save()
