"""The Falkon plugin object: wires the client, backend, filler, passkeys and page scripts."""

import json
import logging
import os

import Falkon
from PySide6 import QtCore
from PySide6.QtCore import QPoint
from PySide6.QtGui import QKeySequence, QShortcut
from PySide6.QtWebEngineCore import QWebEngineScript
from PySide6.QtWebEngineWidgets import QWebEngineView
from PySide6.QtWidgets import QMenu, QWidget

from .backend import BACKEND_ID, KeePassXCBackend, notify
from .bridge import Bridge
from .filler import SAFE_WORLD, Filler, frames_of, web_views
from .menus import EntriesMenu, KeePassXCButton
from .passkeys import PasskeyBroker
from .protocol import KeePassXCClient
from .settings import SettingsDialog
from .store import Store
from .urls import is_web

log = logging.getLogger("keepassxc_falkon")

_DIR = os.path.dirname(os.path.abspath(__file__))
_FILL_SCRIPT = "_keepassxc_falkon_fill"
_PASSKEYS_SCRIPT = "_keepassxc_falkon_passkeys"
_PAGE_WORLD = QWebEngineScript.ScriptWorldId.MainWorld
# Falkon's NavigationBar::loadSettings() defaults, for a never-customized bar.
_DEFAULT_TOOLBAR = [
    "button-backforward",
    "button-reloadstop",
    "button-home",
    "locationbar",
    "button-downloads",
    "adblock-icon",
    "button-tools",
]
_BRIDGE_ID = "keepassxc"  # window.external.extra.keepassxc in SafeJsWorld
# Where the focused field is, in the page's CSS pixels: its bottom-left
# corner, or an iframe's top-left when the focus is inside one. As JSON:
# PySide hands a script's arrays and objects back as empty strings.
_FOCUS_POINT_JS = """(function () {
  var e = document.activeElement;
  if (!e || e === document.body || e === document.documentElement) return "null";
  var r = e.getBoundingClientRect();
  return JSON.stringify(e.localName === "iframe" ? [r.left, r.top] : [r.left, r.bottom]);
})()"""


class KeePassXCPlugin(Falkon.PluginInterface, QtCore.QObject):
    def init(self, state: Falkon.PluginInterface.InitState, settingsPath: str) -> None:
        if os.environ.get("KEEPASSXC_FALKON_DEBUG"):
            handler = logging.StreamHandler()
            handler.setFormatter(logging.Formatter("keepassxc_falkon: %(levelname)s %(message)s"))
            log.addHandler(handler)
            log.setLevel(logging.DEBUG)
        app = Falkon.MainApplication.instance()
        self.store = Store(os.path.join(settingsPath, "keepassxc.json"))
        self.client = KeePassXCClient(self.store, parent=self)
        self.filler = Filler(self.client, self.store, parent=self)
        self.passkeys = PasskeyBroker(self.client, parent=self)
        self.bridge = Bridge(self.filler, self.passkeys, parent=self)
        Falkon.ExternalJsObject.registerExtraObject(_BRIDGE_ID, self.bridge)

        self._fill_js = self._read("fill.js")
        self._passkeys_js = self._read("passkeys.js")
        self.install_scripts()
        if state == Falkon.PluginInterface.LateInitState:
            self._inject_into_open_pages()

        self.entries_menu = EntriesMenu(self.client, self.filler, self.store, self.showSettings)
        if self._place_button_once() and state == Falkon.PluginInterface.LateInitState:
            # Open windows read their toolbar layout when they were created.
            notify("The KeePassXC toolbar button appears after you restart Falkon (or add it with Configure Toolbar).")
        self._buttons: dict[Falkon.BrowserWindow, KeePassXCButton] = {}
        self._shortcuts: dict[Falkon.BrowserWindow, QShortcut] = {}
        app.plugins().mainWindowCreated.connect(self._add_button)
        app.plugins().mainWindowDeleted.connect(self._remove_button)
        for window in app.windows():  # enabled at runtime: windows already open
            self._add_button(window)

        self.backend = KeePassXCBackend(self.client, self.filler, self.showSettings)
        pm = app.autoFill().passwordManager()
        pm.registerBackend(BACKEND_ID, self.backend)
        # Falkon picks its backend lazily on first use; if that happened before
        # we registered, honour the saved choice now.
        configured = Falkon.Settings.globalSettings().value("PasswordManager/Backend", "database")
        if configured == BACKEND_ID and pm.activeBackend().name() != self.backend.name():
            pm.switchBackend(BACKEND_ID)
        self.backend.starting = False
        if pm.activeBackend().name() == self.backend.name():
            self.client.status()  # connect early so the first lookup is quick

    def unload(self) -> None:
        app = Falkon.MainApplication.instance()
        for window in list(self._buttons):
            self._remove_button(window)
        app.autoFill().passwordManager().unregisterBackend(self.backend)
        Falkon.ExternalJsObject.unregisterExtraObject(self.bridge)
        self._remove_scripts()

    def testPlugin(self) -> bool:
        return True

    def showSettings(self, parent: QWidget | None = None) -> None:
        SettingsDialog(
            self.client,
            self.store,
            parent,
            on_passkeys_toggled=self.install_scripts,
            on_shortcut_changed=self._update_shortcuts,
        ).exec()

    # --- right-click menu on form fields --------------------------------

    def populateWebViewMenu(self, menu: QMenu, view: Falkon.WebView, r: Falkon.WebHitTestResult) -> None:
        # Falkon's hit test looks only at the top document: a field inside an
        # iframe reports the <iframe> element itself.
        if (r.isContentEditable() or r.tagName() == "iframe") and is_web(view.url()):
            self.entries_menu.add_to_context_menu(menu, view)

    # --- toolbar buttons (one per window) -------------------------------

    def _place_button_once(self) -> bool:
        """Falkon shows a plugin's button only if the toolbar layout lists it.
        Add ours once (before the tools menu); windows created from now on
        pick it up — at startup, that's all of them."""
        if self.store.option("toolbar_button_placed"):
            return False
        settings = Falkon.Settings.globalSettings()
        saved = settings.value("NavigationBar/Layout")  # a list, a lone string, or unset
        if isinstance(saved, str):
            layout = [saved]
        elif isinstance(saved, list) and saved:
            layout = [str(item) for item in saved]
        else:
            layout = list(_DEFAULT_TOOLBAR)
        if KeePassXCButton.ID not in layout:
            at = layout.index("button-tools") if "button-tools" in layout else len(layout)
            layout.insert(at, KeePassXCButton.ID)
            settings.setValue("NavigationBar/Layout", layout)
        self.store.set_option("toolbar_button_placed", True)
        return True

    def _add_button(self, window: Falkon.BrowserWindow) -> None:
        if window in self._buttons:
            return
        button = KeePassXCButton(self.entries_menu, self.client, self.filler)
        window.navigationBar().addToolButton(button)
        self._buttons[window] = button
        shortcut = QShortcut(self._fill_key(), window)
        shortcut.activated.connect(lambda w=window: self.fill_shortcut(w))
        self._shortcuts[window] = shortcut

    def _remove_button(self, window: Falkon.BrowserWindow) -> None:
        button = self._buttons.pop(window, None)
        if button is not None:
            window.navigationBar().removeToolButton(button)
        shortcut = self._shortcuts.pop(window, None)
        if shortcut is not None:
            shortcut.setEnabled(False)
            shortcut.deleteLater()

    # --- the fill shortcut ------------------------------------------------

    def _fill_key(self) -> QKeySequence:
        return QKeySequence.fromString(
            str(self.store.option("fill_shortcut")), QKeySequence.SequenceFormat.PortableText
        )

    def _update_shortcuts(self) -> None:
        key = self._fill_key()
        for shortcut in self._shortcuts.values():
            shortcut.setKey(key)

    def fill_shortcut(self, window: Falkon.BrowserWindow) -> None:
        """Fill the login form in the window's current tab (or offer the
        choice under the focused field)."""
        view = window.weView()
        if view is None or not is_web(view.url()):
            return
        view.page().runJavaScript(
            _FOCUS_POINT_JS, SAFE_WORLD, lambda point: self.entries_menu.fill_or_choose(view, _anchor(view, point))
        )

    # --- scripts --------------------------------------------------------

    @staticmethod
    def _read(name: str) -> str:
        with open(os.path.join(_DIR, name), encoding="utf-8") as f:
            return f.read()

    def _remove_scripts(self) -> None:
        scripts = Falkon.MainApplication.instance().webProfile().scripts()
        for name in (_FILL_SCRIPT, _PASSKEYS_SCRIPT):
            for script in scripts.find(name):
                scripts.remove(script)

    def install_scripts(self) -> None:
        """fill.js in Falkon's isolated world; passkeys.js, if enabled, in the
        page's own world. Both at document creation, before site scripts
        run, in every frame. Applies to pages loaded from now on."""
        self._remove_scripts()
        scripts = Falkon.MainApplication.instance().webProfile().scripts()
        wanted = [(_FILL_SCRIPT, self._fill_js, SAFE_WORLD)]
        if self.store.option("passkeys"):
            wanted.append((_PASSKEYS_SCRIPT, self._passkeys_js, _PAGE_WORLD))
        for name, source, world in wanted:
            script = QWebEngineScript()
            script.setName(name)
            script.setSourceCode(source)
            script.setWorldId(world)
            script.setInjectionPoint(QWebEngineScript.InjectionPoint.DocumentCreation)
            script.setRunsOnSubFrames(True)
            scripts.insert(script)

    def _inject_into_open_pages(self) -> None:
        # Enabled at runtime: pages already open won't run the profile scripts
        # until they navigate. fill.js is idempotent, so just run it there
        # (passkeys need the page reloaded: they must precede site scripts).
        views = web_views()
        for view in views:
            try:
                for frame in frames_of(view.page()):
                    if is_web(frame.url()):
                        frame.runJavaScript(self._fill_js, SAFE_WORLD)
            except RuntimeError:
                continue


def _anchor(view: QWebEngineView, point_json: object) -> QPoint:
    """Global position for the popup: under the focused field when it's on
    screen, else the middle of the page."""
    try:
        point = json.loads(point_json) if isinstance(point_json, str) else None
    except ValueError:
        point = None
    if isinstance(point, list) and len(point) == 2 and all(isinstance(c, int | float) for c in point):
        zoom = view.zoomFactor()
        local = QPoint(int(point[0] * zoom), int(point[1] * zoom))
        if view.rect().contains(local):
            return view.mapToGlobal(local)
    return view.mapToGlobal(view.rect().center())
