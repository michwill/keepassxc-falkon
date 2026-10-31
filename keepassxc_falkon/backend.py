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

import Falkon
from PySide6.QtCore import QByteArray, QUrl
from PySide6.QtWidgets import QApplication

from . import protocol
from .urls import host_key, is_web, lookup_url, origin

log = logging.getLogger("keepassxc_falkon")

BACKEND_ID = "keepassxc"
SYNC_WAIT_MS = 400


def notify(text):
    app = Falkon.MainApplication.instance()
    if app is not None:
        app.desktopNotifications().showNotification("KeePassXC", text)


class KeePassXCBackend(Falkon.PasswordBackend):
    def __init__(self, client, filler, open_settings):
        Falkon.PasswordBackend.__init__(self)
        self._client = client
        self._filler = filler
        self._open_settings = open_settings
        self._origins = {}          # host key -> origin seen for it
        self._pending_saves = []    # waiting for the database to unlock
        self.starting = True        # no prompts while Falkon starts up
        client.databaseUnlocked.connect(self._retry_saves)

    # --- identity / settings ------------------------------------------

    def name(self):
        return "KeePassXC"

    def hasSettings(self):
        return True

    def showSettings(self, parent):
        self._open_settings(parent)

    def setActive(self, active):
        Falkon.PasswordBackend.setActive(self, active)
        if active and not self.starting:
            # Picked in Preferences: connect now, while the user is looking.
            self._client.associate()

    # --- lookups --------------------------------------------------------

    def getEntries(self, url):
        url = QUrl(url)
        if not is_web(url):
            return []
        self._origins[host_key(url)] = origin(url)
        key = lookup_url(url)
        if self._client.cached_logins(key) is None and not self._filler.has_login_form(url):
            return []
        job = self._client.get_logins(key)
        if not job.done:
            # Don't stall Falkon twice on the same slow lookup (it asks for
            # usernames and then entries in a row on every page load).
            if getattr(job, "sync_timed_out", False) or not self._client.wait(job, SYNC_WAIT_MS):
                job.sync_timed_out = True
                return []
        if job.error is not None:
            return []
        host = host_key(url)
        return [self._entry(host, login) for login in job.result]

    def getAllEntries(self):
        # KeePassXC only answers per-site lookups; the database stays there.
        return []

    @staticmethod
    def _entry(host, login):
        entry = Falkon.PasswordEntry()
        entry.id = login.uuid
        entry.host = host
        entry.username = login.login
        entry.password = login.password
        entry.data = QByteArray()
        return entry

    # --- saving ---------------------------------------------------------

    def addEntry(self, entry):
        self._save(entry.host, entry.username, entry.password, None)

    def updateEntry(self, entry):
        uuid = entry.id if isinstance(entry.id, str) and entry.id else None
        self._save(entry.host, entry.username, entry.password, uuid)
        return True

    def _save(self, host, username, password, uuid):
        url = self._origins.get(host) or f"https://{host}"
        job = self._client.save_login(url, username, password, uuid, trigger_unlock=True)
        job.then(lambda j: self._saved(j, (host, username, password, uuid)))

    def _saved(self, job, save):
        if job.error is None:
            return
        code = job.error.code
        if code == protocol.DATABASE_NOT_OPENED:
            self._pending_saves.append(save)
            notify("The database is locked. The password will be saved once you unlock it.")
        elif code == protocol.NOT_ASSOCIATED:
            # The user just asked to save: ask KeePassXC to connect, then retry.
            self._client.associate(callback=lambda j: j.error is None and self._save(*save))
        elif code == protocol.NOT_RUNNING:
            notify("KeePassXC isn't running, so the password wasn't saved.")
        else:
            notify(f"The password wasn't saved: {job.error}")

    def _retry_saves(self):
        saves, self._pending_saves = self._pending_saves, []
        for host, username, password, uuid in saves:
            self._save(host, username, password, uuid)

    # --- filling --------------------------------------------------------

    def updateLastUsed(self, entry):
        popup = QApplication.activePopupWidget()
        if popup is None or popup.metaObject().className() != "AutoFillWidget":
            return      # Falkon's own page-load replay: the Filler handles that
        window = Falkon.MainApplication.instance().getWindow()
        view = window.weView() if window is not None else None
        if view is not None:
            self._filler.fill_view(view, view.url(), entry.username, entry.password)

    # --- deletion: never touches KeePassXC --------------------------------

    def removeEntry(self, entry):
        log.info("not deleting %s@%s: manage KeePassXC entries in KeePassXC", entry.username, entry.host)

    def removeAll(self):
        log.info("not deleting anything: manage KeePassXC entries in KeePassXC")
