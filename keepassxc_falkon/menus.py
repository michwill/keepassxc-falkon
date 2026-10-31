"""KeePassXC menus: the toolbar button and the login-field context menu.

Both list the entries for the current tab, grouped by site: the page itself,
plus any frame on another site that showed login fields (a login iframe),
each looked up for the URL Chromium reports for that frame. In both, clicking
an entry fills it; the toolbar menu also lists Copy username / Copy password
/ Copy TOTP under each entry.
"""

import os
import time
from collections.abc import Callable

import Falkon
import shiboken6
from PySide6.QtCore import QMimeData, QPoint, Qt, QTimer, QUrl
from PySide6.QtGui import QCursor, QGuiApplication, QIcon
from PySide6.QtWebEngineWidgets import QWebEngineView
from PySide6.QtWidgets import QMenu, QWidget

from . import protocol
from .filler import Filler, frames_of
from .protocol import Job, KeePassXCClient, KeePassXCError, Login
from .store import Store
from .urls import is_web, lookup_url, origin

_DIR = os.path.dirname(os.path.abspath(__file__))
# How long a click waits for KeePassXC before deciding it's asking the user.
WAIT_MS = 600
# A menu still opens if KeePassXC's access dialog is answered within this
# long; after that, the user has likely moved on.
MAX_DEFER_S = 120
# Clipboard managers (Klipper, …) skip data marked like this; KeePassXC
# marks what it copies the same way.
SECRET_HINT = "x-kde-passwordManagerHint"


def app_icon() -> QIcon:
    return QIcon.fromTheme("keepassxc", QIcon(os.path.join(_DIR, "icon.svg")))


def copy_text(text: str, secret: bool = False, clear_after_s: int = 0) -> None:
    clipboard = QGuiApplication.clipboard()
    mime = QMimeData()
    mime.setText(text)
    if secret:
        mime.setData(SECRET_HINT, b"secret")
    clipboard.setMimeData(mime)
    if secret and clear_after_s > 0:

        def wipe() -> None:
            if clipboard.text() == text:  # unless something else was copied since
                clipboard.clear()

        QTimer.singleShot(clear_after_s * 1000, wipe)


# The tab's lookups: (site URL, its get-logins job).
Lookups = list[tuple[QUrl, Job]]


def _info(menu: QMenu, text: str) -> None:
    menu.addAction(text).setEnabled(False)


class EntriesMenu:
    def __init__(
        self, client: KeePassXCClient, filler: Filler, store: Store, open_settings: Callable[[QWidget | None], None]
    ) -> None:
        self._client = client
        self._filler = filler
        self._store = store
        self._open_settings = open_settings
        self._popup: QMenu | None = None
        self._waiting: object | None = None  # the request when_answered will show

    def sites(self, view: QWebEngineView) -> list[QUrl]:
        """One URL per site to look up: the page, then login frames elsewhere."""
        found: dict[str, QUrl] = {}
        for frame in frames_of(view.page()):
            url = frame.url()
            if not is_web(url) or origin(url) in found:
                continue
            if frame.isMainFrame() or self._filler.has_login_form(url):
                found[origin(url)] = url
        return list(found.values())

    def match_count(self, view: QWebEngineView) -> int:
        """Entries already looked up for this tab's frames (no new requests)."""
        uuids: set[str] = set()
        for frame in frames_of(view.page()):
            if is_web(frame.url()):
                uuids.update(login.uuid for login in self._client.cached_logins(lookup_url(frame.url())) or ())
        return len(uuids)

    def lookups(self, view: QWebEngineView) -> Lookups:
        """Ask KeePassXC about every site in the tab, waiting up to WAIT_MS
        for the answers (one shared budget: requests are serialized)."""
        jobs = [(url, self._client.get_logins(lookup_url(url))) for url in self.sites(view)]
        for _url, job in jobs:
            if not job.done:
                self._client.wait(job, WAIT_MS)
        return jobs

    def when_answered(self, view: QWebEngineView, show: Callable[[Lookups], None], jobs: Lookups | None = None) -> None:
        """Call ``show(jobs)`` once KeePassXC has answered the tab's lookups:
        right away if it answers within WAIT_MS, otherwise when it does.

        Taking longer means KeePassXC is asking the user (its access dialog).
        A menu opened meanwhile would hold the pointer grab, as Qt popups do,
        so the user's first click on that dialog would only close the menu.
        Only the latest request shows, and only while its tab is on screen.
        """
        if jobs is None:
            jobs = self.lookups(view)
        self._waiting = token = object()
        pending = [job for _url, job in jobs if not job.done]
        if not pending:
            show(jobs)
            return
        asked = time.monotonic()

        def answered(_job: Job) -> None:
            if self._waiting is not token or not all(job.done for job in pending):
                return
            self._waiting = None
            if shiboken6.isValid(view) and view.isVisible() and time.monotonic() - asked < MAX_DEFER_S:
                show(jobs)

        for job in pending:
            job.then(answered)

    def fill_or_choose(self, view: QWebEngineView, at: QPoint, jobs: Lookups | None = None) -> None:
        """The fill shortcut: a single matching entry is filled straight away;
        otherwise the entries (or what's wrong) pop up at ``at``, the first one
        highlighted so Enter takes it."""
        self.when_answered(view, lambda answered: self._fill_or_choose(view, at, answered), jobs)

    def _fill_or_choose(self, view: QWebEngineView, at: QPoint, jobs: Lookups) -> None:
        found = [(url, login) for url, job in jobs if job.error is None for login in job.result]
        if len(found) == 1:
            url, login = found[0]
            self._fill(view, url, login)
            return
        menu = QMenu(view)
        self.populate(menu, view, jobs, direct_fill=True)
        menu.popup(at)
        first = next((a for a in menu.actions() if a.isEnabled() and not a.isSeparator()), None)
        if first is not None:
            menu.setActiveAction(first)
        self._popup = menu  # keep it alive while shown

    def add_to_context_menu(self, menu: QMenu, view: QWebEngineView) -> None:
        """A KeePassXC submenu with the tab's entries in a login field's
        right-click menu. If KeePassXC is asking the user first, Falkon's
        menu would keep that dialog's first click to itself (see
        ``when_answered``): close it, and once KeePassXC answers, fill or
        offer the entries where the user right-clicked."""
        jobs = self.lookups(view)
        if all(job.done for _url, job in jobs):
            self.populate(menu.addMenu(app_icon(), "KeePassXC"), view, jobs, direct_fill=True)
            return
        QTimer.singleShot(0, menu, menu.close)
        self.fill_or_choose(view, QCursor.pos(), jobs)

    def populate(self, menu: QMenu, view: QWebEngineView, jobs: Lookups, direct_fill: bool) -> None:
        """Fill ``menu`` from answered lookups (see ``when_answered``)."""
        problem = next(
            (
                job.error
                for _url, job in jobs
                if job.error is not None
                and job.error.code in (protocol.NOT_RUNNING, protocol.DATABASE_NOT_OPENED, protocol.NOT_ASSOCIATED)
            ),
            None,
        )
        if not jobs:
            _info(menu, "No website in this tab")
        elif problem is not None:
            self._add_problem(menu, problem)
        else:
            for i, (url, job) in enumerate(jobs):
                if len(jobs) > 1:
                    if i and not direct_fill:
                        menu.addSeparator()
                    header = menu.addAction(url.host())
                    header.setEnabled(False)
                    font = header.font()
                    font.setBold(True)
                    header.setFont(font)
                self._add_site(menu, view, url, job, direct_fill)
        menu.addSeparator()
        menu.addAction("KeePassXC settings…").triggered.connect(lambda: self._open_settings(view))

    def _add_problem(self, menu: QMenu, error: KeePassXCError) -> None:
        if error.code == protocol.DATABASE_NOT_OPENED:
            _info(menu, "The database is locked")
            menu.addAction("Unlock database").triggered.connect(lambda: self._client.unlock())
        elif error.code == protocol.NOT_ASSOCIATED:
            _info(menu, "Falkon isn't connected to this database")
            menu.addAction("Connect to database…").triggered.connect(lambda: self._client.associate())
        else:
            _info(menu, "KeePassXC isn't running (or browser integration is off)")

    def _add_site(self, menu: QMenu, view: QWebEngineView, url: QUrl, job: Job, direct_fill: bool) -> None:
        if job.error is not None:
            _info(menu, str(job.error))
            return
        if not job.result:
            _info(menu, "No entries for this site")
            return
        logins: list[Login] = job.result
        for i, login in enumerate(logins):
            label = login.login or "(no username)"
            if login.name and login.name != login.login:
                label += f" \u2014 {login.name}"
            if login.expired:
                label += " (expired)"
            if direct_fill:
                menu.addAction(label).triggered.connect(lambda _c=False, e=login: self._fill(view, url, e))
                continue
            # No submenus: on a maximized window a submenu of this menu opened
            # half off the right screen edge on the user's desktop (Falkon's own
            # submenus flipped left fine; we never found why). So each entry is
            # a group in the menu itself: its name, bold like a default action,
            # fills it; its copy actions follow.
            if i:
                menu.addSeparator()
            fill = menu.addAction(app_icon(), label)
            font = fill.font()
            font.setBold(True)
            fill.setFont(font)
            fill.triggered.connect(lambda _c=False, e=login: self._fill(view, url, e))
            copy_icon = QIcon.fromTheme("edit-copy")
            menu.addAction(copy_icon, "Copy username").triggered.connect(lambda _c=False, e=login: copy_text(e.login))
            menu.addAction(copy_icon, "Copy password").triggered.connect(
                lambda _c=False, e=login: copy_text(e.password, secret=True, clear_after_s=self._clear_after())
            )
            if login.has_totp:
                menu.addAction(copy_icon, "Copy TOTP").triggered.connect(lambda _c=False, e=login: self._copy_totp(e))

    def _fill(self, view: QWebEngineView, url: QUrl, login: Login) -> None:
        self._filler.fill_view(view, url, login.login, login.password)

    def _copy_totp(self, login: Login) -> None:
        def got(job: Job) -> None:
            if job.error is None and job.result:
                copy_text(job.result, secret=True, clear_after_s=self._clear_after())

        self._client.get_totp(login.uuid, callback=got)

    def _clear_after(self) -> int:
        return int(self._store.option("clipboard_clear_seconds"))


class KeePassXCButton(Falkon.AbstractButtonInterface):
    """Navigation-bar button: the badge counts matching entries for the
    current tab; the icon dims when KeePassXC can't be used."""

    ID = "keepassxc-falkon"

    def __init__(self, menus: EntriesMenu, client: KeePassXCClient, filler: Filler) -> None:
        super().__init__()
        self._menus = menus
        self._client = client
        self._menu: QMenu | None = None
        self._icon = app_icon()
        self._icon_off = QIcon(self._icon.pixmap(64, 64, QIcon.Mode.Disabled))
        self.setTitle("KeePassXC")
        self.clicked.connect(self._on_clicked)
        self.webViewChanged.connect(self._on_view)
        client.stateChanged.connect(self.refresh)
        filler.lookedUp.connect(self.refresh)
        self.refresh()

    def id(self) -> str:
        return self.ID

    def name(self) -> str:
        return "KeePassXC"

    def _on_view(self, view: Falkon.WebView | None) -> None:
        if view is not None:
            view.urlChanged.connect(self.refresh, Qt.ConnectionType.UniqueConnection)
        self.refresh()

    def refresh(self, *_: object) -> None:
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

    def _on_clicked(self, controller: Falkon.AbstractButtonInterface.ClickController) -> None:
        view = self.webView()
        if view is None:
            menu = QMenu()
            _info(menu, "No website in this tab")
            self._popup_from_click(menu, controller)
            return
        clicking = True  # Falkon's click controller is only valid during this call

        def show(jobs: Lookups) -> None:
            menu = QMenu(view.window())
            self._menus.populate(menu, view, jobs, direct_fill=False)
            if clicking:
                self._popup_from_click(menu, controller)
            else:  # KeePassXC asked the user first
                menu.popup(self._below_button(view, menu))
                self._menu = menu

        self._menus.when_answered(view, show)
        clicking = False

    def _popup_from_click(self, menu: QMenu, controller: Falkon.AbstractButtonInterface.ClickController) -> None:
        menu.aboutToHide.connect(controller.callPopupClosed)
        menu.popup(controller.callPopupPosition(menu.sizeHint()))
        self._menu = menu  # keep it alive while shown

    def _below_button(self, view: QWebEngineView, menu: QMenu) -> QPoint:
        """Where Falkon opens a button's menu: under it, right-aligned."""
        for widget in view.window().findChildren(QWidget):
            if widget.property("button-id") == self.ID and widget.isVisible():
                return widget.mapToGlobal(QPoint(widget.width() - menu.sizeHint().width(), widget.height()))
        return QCursor.pos()
