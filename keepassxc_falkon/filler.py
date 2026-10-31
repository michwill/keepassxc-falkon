"""Filling credentials into pages.

Falkon's own autofill replays a stored form submission, matching inputs by
``name`` — data KeePassXC entries don't have. So filling is done here:
``fill.js`` (in Falkon's isolated SafeJsWorld) finds login fields and
reports them; this side decides what to fill and pushes it into the frame.

Trust model: the report from JS is only a hint. Credentials are looked up
for the URL *Chromium* reports for a frame (``QWebEngineFrame.url()``),
and pushed only into frames whose URL is exactly that one. The fill script
is additionally guarded by the reporting document's token, which lives in
the isolated world where page scripts can't read it.
"""

import json
import logging
import time
from collections import OrderedDict
from collections.abc import Callable, Mapping
from typing import TYPE_CHECKING

import Falkon
from PySide6.QtCore import QObject, QUrl, Signal
from PySide6.QtWebEngineCore import QWebEngineFrame, QWebEnginePage, QWebEngineScript
from PySide6.QtWebEngineWidgets import QWebEngineView
from PySide6.QtWidgets import QApplication

from . import protocol
from .urls import is_web, lookup_url, origin, page_key

if TYPE_CHECKING:
    from .protocol import Job, KeePassXCClient
    from .store import Store

log = logging.getLogger("keepassxc_falkon")

SAFE_WORLD = QWebEngineScript.ScriptWorldId.ApplicationWorld
UNLOCK_THROTTLE_S = 30
MAX_FORM_PAGES = 500


def web_views() -> list[QWebEngineView]:
    """Every open web view — tabs and popup windows alike. Callers keep the
    list alive while using pages: PyFalkon ties a page's Python wrapper to
    its view's, and a collected view wrapper takes the page's down with it."""
    return [w for w in QApplication.allWidgets() if isinstance(w, QWebEngineView)]


def frames_of(page: QWebEnginePage) -> list[QWebEngineFrame]:
    out, stack = [], [page.mainFrame()]
    while stack:
        frame = stack.pop()
        if frame.isValid():
            out.append(frame)
            stack.extend(frame.children())
    return out


def frames_at(views: list[QWebEngineView], key: QUrl) -> list[tuple[QWebEngineFrame, QWebEngineView]]:
    """``(frame, view)`` for every frame showing ``key``. Keep ``views``
    referenced while using the frames."""
    found: list[tuple[QWebEngineFrame, QWebEngineView]] = []
    for view in views:
        try:
            found += [(f, view) for f in frames_of(view.page()) if page_key(f.url()) == key]
        except RuntimeError:
            continue    # a view Qt already deleted
    return found


def fill_script(creds: Mapping[str, object], token: str | None = None) -> str:
    call = "k.fill(" + json.dumps(creds) + ")"
    guard = "k && k.token === " + json.dumps(token) if token else "k"
    return "(function(){var k=window.__kpxcFalkon;return !!(" + guard + ") && " + call + ";})()"


class Filler(QObject):
    lookedUp = Signal()     # a page's login lookup finished (toolbar badge)

    def __init__(self, client: "KeePassXCClient", store: "Store", parent: QObject | None = None,
                 views: Callable[[], list[QWebEngineView]] = web_views) -> None:
        super().__init__(parent)
        self._client = client
        self._store = store
        self._views = views
        self._last_unlock_request = 0.0
        self._form_pages: OrderedDict[str, bool] = OrderedDict()   # lookup URLs that showed login fields
        client.databaseUnlocked.connect(self.rescan_all)

    # --- reports from pages -------------------------------------------

    def has_login_form(self, url: QUrl) -> bool:
        """Whether a frame at ``url`` has shown login fields this session."""
        return lookup_url(url) in self._form_pages

    def login_form_found(self, token: str, href: str, info: str) -> None:
        url = QUrl(href)
        if not is_web(url) or not token:
            return
        key = page_key(url)
        _views = self._views()
        if not frames_at(_views, key):
            return      # not a frame we can see (navigated away already?)
        lookup = lookup_url(url)
        self._form_pages[lookup] = True
        self._form_pages.move_to_end(lookup)
        while len(self._form_pages) > MAX_FORM_PAGES:
            self._form_pages.popitem(last=False)
        try:
            has_password = bool(json.loads(info).get("password"))
        except (ValueError, AttributeError):
            has_password = True
        self._client.get_logins(lookup, callback=lambda job: self._logins_for_form(job, token, key, has_password))

    def _logins_for_form(self, job: "Job", token: str, key: QUrl, has_password: bool) -> None:
        self.lookedUp.emit()
        if job.error is not None:
            if job.error.code == protocol.DATABASE_NOT_OPENED and has_password:
                self._maybe_request_unlock()
            return
        logins = job.result
        if not logins or not autocomplete_enabled():
            return
        if len(logins) > 1 and not self._store.option("fill_first_of_many"):
            return      # several accounts: the user picks (key icon / context menu)
        best = logins[0]
        creds = {"username": best.login, "password": best.password, "overwrite": False}
        views = self._views()
        for frame, _view in frames_at(views, key):
            frame.runJavaScript(fill_script(creds, token), SAFE_WORLD)

    def _maybe_request_unlock(self) -> None:
        if not self._store.option("unlock_on_login_form"):
            return
        now = time.monotonic()
        if now - self._last_unlock_request < UNLOCK_THROTTLE_S:
            return
        self._last_unlock_request = now
        self._client.unlock()

    # --- explicit fills -----------------------------------------------

    def fill_view(self, view: QWebEngineView, page_url: QUrl, username: str, password: str) -> None:
        """The user picked an entry (looked up for ``page_url``): fill it into
        the view's frames that are on that page's origin, overwriting."""
        page_origin = origin(page_url)
        creds = {"username": username, "password": password, "overwrite": True}
        for frame in frames_of(view.page()):
            url = frame.url()
            if is_web(url) and origin(url) == page_origin:
                frame.runJavaScript(fill_script(creds), SAFE_WORLD)

    def rescan_all(self) -> None:
        views = self._views()
        for view in views:
            try:
                for frame in frames_of(view.page()):
                    if is_web(frame.url()):
                        frame.runJavaScript("window.__kpxcFalkon && window.__kpxcFalkon.rescan()", SAFE_WORLD)
            except RuntimeError:
                continue    # a view Qt already deleted


def autocomplete_enabled() -> bool:
    """Falkon's own "Autocomplete passwords" preference."""
    settings = Falkon.Settings.globalSettings()
    value = settings.value("Web-Browser-Settings/AutoCompletePasswords", True)
    return value if isinstance(value, bool) else str(value).lower() != "false"
