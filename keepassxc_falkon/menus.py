"""KeePassXC menus: the toolbar button and the login-field context menu.

Both list the entries for the current tab, grouped by site: the page itself,
plus any frame on another site that showed login fields (a login iframe),
each looked up for the URL Chromium reports for that frame. The toolbar menu
offers Fill / Copy username / Copy password / Copy TOTP per entry; the
context menu (you right-clicked a field) fills with one click.
"""

import os

import Falkon
from PySide6.QtCore import QMimeData, Qt, QTimer
from PySide6.QtGui import QGuiApplication, QIcon
from PySide6.QtWidgets import QMenu

from . import protocol
from .filler import frames_of
from .urls import is_web, lookup_url, origin

_DIR = os.path.dirname(os.path.abspath(__file__))
WAIT_MS = 600
# Clipboard managers (Klipper, …) skip data marked like this; KeePassXC
# marks what it copies the same way.
SECRET_HINT = "x-kde-passwordManagerHint"


def app_icon():
    return QIcon.fromTheme("keepassxc", QIcon(os.path.join(_DIR, "icon.svg")))


def copy_text(text, secret=False, clear_after_s=0):
    clipboard = QGuiApplication.clipboard()
    mime = QMimeData()
    mime.setText(text)
    if secret:
        mime.setData(SECRET_HINT, b"secret")
    clipboard.setMimeData(mime)
    if secret and clear_after_s > 0:
        # Wipe it later, unless something else has been copied since.
        QTimer.singleShot(clear_after_s * 1000, lambda: clipboard.text() == text and clipboard.clear())


def _info(menu, text):
    menu.addAction(text).setEnabled(False)


class EntriesMenu:
    def __init__(self, client, filler, store, open_settings):
        self._client = client
        self._filler = filler
        self._store = store
        self._open_settings = open_settings

    def sites(self, view):
        """One URL per site to look up: the page, then login frames elsewhere."""
        found = {}
        for frame in frames_of(view.page()):
            url = frame.url()
            if not is_web(url) or origin(url) in found:
                continue
            if frame.isMainFrame() or self._filler.has_login_form(url):
                found[origin(url)] = url
        return list(found.values())

    def match_count(self, view):
        """Entries already looked up for this tab's frames (no new requests)."""
        uuids = set()
        for frame in frames_of(view.page()):
            if is_web(frame.url()):
                uuids.update(login.uuid for login in self._client.cached_logins(lookup_url(frame.url())) or ())
        return len(uuids)

    def populate(self, menu, view, direct_fill):
        sites = self.sites(view)
        jobs = [(url, self._client.get_logins(lookup_url(url))) for url in sites]
        for _url, job in jobs:          # one shared budget: requests are serialized
            if not job.done:
                self._client.wait(job, WAIT_MS)

        problem = next((job.error for _url, job in jobs if job.done and job.error is not None
                        and job.error.code in (protocol.NOT_RUNNING, protocol.DATABASE_NOT_OPENED,
                                               protocol.NOT_ASSOCIATED)), None)
        if not sites:
            _info(menu, "No website in this tab")
        elif problem is not None:
            self._add_problem(menu, problem)
        else:
            for url, job in jobs:
                if len(sites) > 1:
                    header = menu.addAction(url.host())
                    header.setEnabled(False)
                    font = header.font()
                    font.setBold(True)
                    header.setFont(font)
                self._add_site(menu, view, url, job, direct_fill)
                if not job.done:
                    # KeePassXC is asking the user (access dialog): refresh the
                    # open menu once it answers.
                    job.then(lambda _j: self._refresh(menu, view, direct_fill))
        menu.addSeparator()
        menu.addAction("KeePassXC settings…").triggered.connect(lambda: self._open_settings(view))

    def _refresh(self, menu, view, direct_fill):
        if menu.isVisible():
            menu.clear()
            self.populate(menu, view, direct_fill)

    def _add_problem(self, menu, error):
        if error.code == protocol.DATABASE_NOT_OPENED:
            _info(menu, "The database is locked")
            menu.addAction("Unlock database").triggered.connect(lambda: self._client.unlock())
        elif error.code == protocol.NOT_ASSOCIATED:
            _info(menu, "Falkon isn't connected to this database")
            menu.addAction("Connect to database…").triggered.connect(lambda: self._client.associate())
        else:
            _info(menu, "KeePassXC isn't running (or browser integration is off)")

    def _add_site(self, menu, view, url, job, direct_fill):
        if not job.done:
            _info(menu, "Waiting for KeePassXC…")
            return
        if job.error is not None:
            _info(menu, str(job.error))
            return
        if not job.result:
            _info(menu, "No entries for this site")
            return
        for login in job.result:
            label = login.login or "(no username)"
            if login.name and login.name != login.login:
                label += f" — {login.name}"
            if login.expired:
                label += " (expired)"
            fill = (lambda _c=False, l=login, u=url:
                    self._filler.fill_view(view, u, l.login, l.password))
            if direct_fill:
                menu.addAction(label).triggered.connect(fill)
                continue
            sub = menu.addMenu(label)
            sub.addAction("Fill").triggered.connect(fill)
            sub.addAction("Copy username").triggered.connect(
                lambda _c=False, l=login: copy_text(l.login))
            sub.addAction("Copy password").triggered.connect(
                lambda _c=False, l=login: copy_text(l.password, secret=True, clear_after_s=self._clear_after()))
            if login.has_totp:
                sub.addAction("Copy TOTP").triggered.connect(lambda _c=False, l=login: self._copy_totp(l))

    def _copy_totp(self, login):
        self._client.get_totp(login.uuid, callback=lambda job: job.error is None and job.result
                              and copy_text(job.result, secret=True, clear_after_s=self._clear_after()))

    def _clear_after(self):
        return self._store.option("clipboard_clear_seconds")


class KeePassXCButton(Falkon.AbstractButtonInterface):
    """Navigation-bar button: the badge counts matching entries for the
    current tab; the icon dims when KeePassXC can't be used."""

    ID = "keepassxc-falkon"

    def __init__(self, menus, client, filler):
        super().__init__()
        self._menus = menus
        self._client = client
        self._menu = None
        self._icon = app_icon()
        self._icon_off = QIcon(self._icon.pixmap(64, 64, QIcon.Mode.Disabled))
        self.setTitle("KeePassXC")
        self.clicked.connect(self._on_clicked)
        self.webViewChanged.connect(self._on_view)
        client.stateChanged.connect(self.refresh)
        filler.lookedUp.connect(self.refresh)
        self.refresh()

    def id(self):
        return self.ID

    def name(self):
        return "KeePassXC"

    def _on_view(self, view):
        if view is not None:
            view.urlChanged.connect(self.refresh, Qt.ConnectionType.UniqueConnection)
        self.refresh()

    def refresh(self, *_):
        c = self._client
        view = self.webView()
        count = self._menus.match_count(view) if view is not None else 0
        if c.running is False:
            usable, tip = False, "KeePassXC isn't running"
        elif c.locked:
            usable, tip = False, "KeePassXC — database locked"
        elif c.locked is False and not c.associated:
            usable, tip = False, "KeePassXC — not connected to this database"
        else:
            usable = True
            tip = f"KeePassXC — {count} matching entr{'y' if count == 1 else 'ies'}" if count else "KeePassXC"
        self.setIcon(self._icon if usable else self._icon_off)
        self.setToolTip(tip)
        self.setBadgeText(str(count) if count and usable else "")

    def _on_clicked(self, controller):
        view = self.webView()
        menu = QMenu()
        if view is None:
            _info(menu, "No website in this tab")
        else:
            self._menus.populate(menu, view, direct_fill=False)
        menu.aboutToHide.connect(controller.callPopupClosed)
        menu.popup(controller.callPopupPosition(menu.sizeHint()))
        self._menu = menu       # keep it alive while shown
