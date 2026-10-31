"""KeePassXC as a Falkon password backend.

Registered with Falkon's PasswordManager, it shows up under Preferences →
Passwords → Backend. Falkon then routes its password plumbing here:

- ``getEntries(url)`` — on every page load (to fill and to light the key
  icon in the location bar) and before offering to save a submitted form.
  We only ask KeePassXC for pages where fill.js found login fields (like
  keepassxc-browser): asking on every page would raise KeePassXC's access
  dialog all over a site you have an entry for, and hand it your history.
  Falkon calls this synchronously, so we answer from the client's cache or
  block briefly on KeePassXC's local socket; a lookup that takes longer
  (KeePassXC showing its access dialog) finishes in the background and the
  page gets filled by the Filler when it does.
- ``addEntry`` / ``updateEntry`` — "Remember"/"Update" on Falkon's save bar;
  written to KeePassXC (``set-login``).
- ``updateLastUsed`` — Falkon calls it right before replaying an entry into
  the page. When that's the user's pick from the key-icon menu, we do the
  filling ourselves (Falkon's replay needs stored form data we don't have).

Passwords never leave KeePassXC for Falkon's own storage: the backend lists
no entries in Preferences, and "remove" never deletes anything in KeePassXC.
"""

import logging
from collections.abc import Callable

import Falkon
from PySide6.QtCore import QByteArray, QUrl
from PySide6.QtWidgets import QApplication, QWidget

from . import protocol
from .filler import Filler
from .protocol import Job, KeePassXCClient, Login
from .urls import host_key, is_web, lookup_url, origin

log = logging.getLogger("keepassxc_falkon")

BACKEND_ID = "keepassxc"
SYNC_WAIT_MS = 400


# (host, username, password, uuid) of a save to (re)try
Save = tuple[str, str, str, str | None]


def notify(text: str) -> None:
    Falkon.MainApplication.instance().desktopNotifications().showNotification("KeePassXC", text)


class KeePassXCBackend(Falkon.PasswordBackend):
    def __init__(
        self, client: KeePassXCClient, filler: Filler, open_settings: Callable[[QWidget | None], None]
    ) -> None:
        Falkon.PasswordBackend.__init__(self)
        self._client = client
        self._filler = filler
        self._open_settings = open_settings
        self._origins: dict[str, str] = {}  # host key -> origin seen for it
        self._pending_saves: list[Save] = []  # waiting for the database to unlock
        self.starting = True  # no prompts while Falkon starts up
        client.databaseUnlocked.connect(self._retry_saves)

    # --- identity / settings ------------------------------------------

    def name(self) -> str:
        return "KeePassXC"

    def hasSettings(self) -> bool:
        return True

    def showSettings(self, parent: QWidget | None) -> None:
        self._open_settings(parent)

    def setActive(self, active: bool) -> None:
        Falkon.PasswordBackend.setActive(self, active)
        if active and not self.starting:
            # Picked in Preferences: connect now, while the user is looking.
            self._client.associate()

    # --- lookups --------------------------------------------------------

    def getEntries(self, url: QUrl) -> list[Falkon.PasswordEntry]:
        if not is_web(url):
            return []
        self._origins[host_key(url)] = origin(url)
        key = lookup_url(url)
        if self._client.cached_logins(key) is None and not self._filler.has_login_form(url):
            return []
        job = self._client.get_logins(key)
        # Don't stall Falkon twice on the same slow lookup (it asks for
        # usernames and then entries in a row on every page load).
        if not job.done and (job.sync_timed_out or not self._client.wait(job, SYNC_WAIT_MS)):
            job.sync_timed_out = True
            return []
        if job.error is not None:
            return []
        host = host_key(url)
        return [self._entry(host, login) for login in job.result]

    def getAllEntries(self) -> list[Falkon.PasswordEntry]:
        # KeePassXC only answers per-site lookups; the database stays there.
        return []

    @staticmethod
    def _entry(host: str, login: Login) -> Falkon.PasswordEntry:
        entry = Falkon.PasswordEntry()
        entry.id = login.uuid
        entry.host = host
        entry.username = login.login
        entry.password = login.password
        entry.data = QByteArray()
        return entry

    # --- saving ---------------------------------------------------------

    def addEntry(self, entry: Falkon.PasswordEntry) -> None:
        self._save(entry.host, entry.username, entry.password, None)

    def updateEntry(self, entry: Falkon.PasswordEntry) -> bool:
        uuid = entry.id if isinstance(entry.id, str) and entry.id else None
        self._save(entry.host, entry.username, entry.password, uuid)
        return True

    def _save(self, host: str, username: str, password: str, uuid: str | None) -> None:
        url = self._origins.get(host) or f"https://{host}"
        job = self._client.save_login(url, username, password, uuid, trigger_unlock=True)
        job.then(lambda j: self._saved(j, (host, username, password, uuid)))

    def _saved(self, job: Job, save: Save) -> None:
        if job.error is None:
            return
        code = job.error.code
        if code == protocol.DATABASE_NOT_OPENED:
            self._pending_saves.append(save)
            notify("The database is locked. The password will be saved once you unlock it.")
        elif code == protocol.NOT_ASSOCIATED:
            # The user just asked to save: ask KeePassXC to connect, then retry.
            def connected(j: Job) -> None:
                if j.error is None:
                    self._save(*save)

            self._client.associate(callback=connected)
        elif code == protocol.NOT_RUNNING:
            notify("KeePassXC isn't running, so the password wasn't saved.")
        else:
            notify(f"The password wasn't saved: {job.error}")

    def _retry_saves(self) -> None:
        saves, self._pending_saves = self._pending_saves, []
        for host, username, password, uuid in saves:
            self._save(host, username, password, uuid)

    # --- filling --------------------------------------------------------

    def updateLastUsed(self, entry: Falkon.PasswordEntry) -> None:
        popup = QApplication.activePopupWidget()
        if popup is None or popup.metaObject().className() != "AutoFillWidget":
            return  # Falkon's own page-load replay: the Filler handles that
        window = Falkon.MainApplication.instance().getWindow()
        view = window.weView() if window is not None else None
        if view is not None:
            self._filler.fill_view(view, view.url(), entry.username, entry.password)

    # --- deletion: never touches KeePassXC --------------------------------

    def removeEntry(self, entry: Falkon.PasswordEntry) -> None:
        log.info("not deleting %s@%s: manage KeePassXC entries in KeePassXC", entry.username, entry.host)

    def removeAll(self) -> None:
        log.info("not deleting anything: manage KeePassXC entries in KeePassXC")
