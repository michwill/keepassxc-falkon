"""The Falkon plugin object: wires the client, backend, filler, passkeys and page scripts."""

import logging
import os

import Falkon
from PySide6 import QtCore
from PySide6.QtWebEngineCore import QWebEngineScript
from PySide6.QtWidgets import QMenu, QWidget

from .backend import BACKEND_ID, KeePassXCBackend
from .bridge import Bridge
from .filler import SAFE_WORLD, Filler, frames_of, web_views
from .menus import EntriesMenu, KeePassXCButton, app_icon
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
_DEFAULT_TOOLBAR = ["button-backforward", "button-reloadstop", "button-home", "locationbar",
                    "button-downloads", "adblock-icon", "button-tools"]
_BRIDGE_ID = "keepassxc"     # window.external.extra.keepassxc in SafeJsWorld


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
        self._place_button_once()
        self._buttons: dict[Falkon.BrowserWindow, KeePassXCButton] = {}
        app.plugins().mainWindowCreated.connect(self._add_button)
        app.plugins().mainWindowDeleted.connect(self._remove_button)
        for window in app.windows():     # enabled at runtime: windows already open
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
            self.client.status()     # connect early so the first lookup is quick

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
        SettingsDialog(self.client, self.store, parent, on_passkeys_toggled=self.install_scripts).exec()

    # --- right-click menu on form fields --------------------------------

    def populateWebViewMenu(self, menu: QMenu, view: Falkon.WebView, r: Falkon.WebHitTestResult) -> None:
        # Falkon's hit test looks only at the top document: a field inside an
        # iframe reports the <iframe> element itself.
        if (r.isContentEditable() or r.tagName() == "iframe") and is_web(view.url()):
            self.entries_menu.populate(menu.addMenu(app_icon(), "KeePassXC"), view, direct_fill=True)

    # --- toolbar buttons (one per window) -------------------------------

    def _place_button_once(self) -> None:
        """Falkon shows a plugin's button only if the toolbar layout lists it.
        Add ours once (before the tools menu); windows created from now on
        pick it up — at startup, that's all of them."""
        if self.store.option("toolbar_button_placed"):
            return
        settings = Falkon.Settings.globalSettings()
        saved = settings.value("NavigationBar/Layout")     # a list, a lone string, or unset
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

    def _add_button(self, window: Falkon.BrowserWindow) -> None:
        if window in self._buttons:
            return
        button = KeePassXCButton(self.entries_menu, self.client, self.filler)
        window.navigationBar().addToolButton(button)
        self._buttons[window] = button

    def _remove_button(self, window: Falkon.BrowserWindow) -> None:
        button = self._buttons.pop(window, None)
        if button is not None:
            window.navigationBar().removeToolButton(button)

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
