"""The Falkon plugin object: wires the client, backend, filler and page script."""

import logging
import os

import Falkon
from PySide6 import QtCore
from PySide6.QtGui import QIcon
from PySide6.QtWebEngineCore import QWebEngineScript

from .backend import BACKEND_ID, SYNC_WAIT_MS, KeePassXCBackend
from .filler import SAFE_WORLD, Filler, frames_of, web_views
from .protocol import DATABASE_NOT_OPENED, NOT_ASSOCIATED, NOT_RUNNING, KeePassXCClient
from .settings import SettingsDialog
from .store import Store
from .urls import is_web, lookup_url

log = logging.getLogger("keepassxc_falkon")

_DIR = os.path.dirname(os.path.abspath(__file__))
_SCRIPT_NAME = "_keepassxc_falkon_fill"
_BRIDGE_ID = "keepassxc"     # window.external.extra.keepassxc in SafeJsWorld


def _icon():
    return QIcon.fromTheme("keepassxc", QIcon(os.path.join(_DIR, "icon.svg")))


class KeePassXCPlugin(Falkon.PluginInterface, QtCore.QObject):
    def init(self, state, settingsPath):
        if os.environ.get("KEEPASSXC_FALKON_DEBUG"):
            handler = logging.StreamHandler()
            handler.setFormatter(logging.Formatter("keepassxc_falkon: %(levelname)s %(message)s"))
            log.addHandler(handler)
            log.setLevel(logging.DEBUG)
        app = Falkon.MainApplication.instance()
        self.store = Store(os.path.join(settingsPath, "keepassxc.json"))
        self.client = KeePassXCClient(self.store, parent=self)
        self.filler = Filler(self.client, self.store, parent=self)
        Falkon.ExternalJsObject.registerExtraObject(_BRIDGE_ID, self.filler.bridge)

        with open(os.path.join(_DIR, "fill.js"), encoding="utf-8") as f:
            self._fill_js = f.read()
        self._install_script(app)
        if state == Falkon.PluginInterface.LateInitState:
            self._inject_into_open_pages()

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

    def unload(self):
        app = Falkon.MainApplication.instance()
        app.autoFill().passwordManager().unregisterBackend(self.backend)
        Falkon.ExternalJsObject.unregisterExtraObject(self.filler.bridge)
        scripts = app.webProfile().scripts()
        for script in scripts.find(_SCRIPT_NAME):
            scripts.remove(script)

    def testPlugin(self):
        return True

    def showSettings(self, parent=None):
        SettingsDialog(self.client, self.store, parent).exec()

    # --- right-click menu on form fields --------------------------------

    def populateWebViewMenu(self, menu, view, r):
        if r.isContentEditable() and is_web(view.url()):
            self.fill_menu(menu.addMenu(_icon(), "KeePassXC"), view)

    def fill_menu(self, sub, view):
        """The entries for ``view``'s page; picking one fills it in."""
        url = view.url()
        job = self.client.get_logins(lookup_url(url))
        if not job.done:
            self.client.wait(job, SYNC_WAIT_MS)

        if not job.done:
            sub.addAction("Waiting for KeePassXC…").setEnabled(False)
        elif job.error is None and job.result:
            for login in job.result:
                label = login.login or "(no username)"
                if login.name and login.name != login.login:
                    label += f" \u2014 {login.name}"
                action = sub.addAction(label)
                action.triggered.connect(
                    lambda _checked=False, l=login: self.filler.fill_view(view, url, l.login, l.password))
        elif job.error is None:
            sub.addAction("No entries for this site").setEnabled(False)
        elif job.error.code == DATABASE_NOT_OPENED:
            sub.addAction("Unlock database").triggered.connect(lambda: self.client.unlock())
        elif job.error.code == NOT_ASSOCIATED:
            sub.addAction("Connect to database…").triggered.connect(lambda: self.client.associate())
        elif job.error.code == NOT_RUNNING:
            sub.addAction("KeePassXC isn't running").setEnabled(False)
        else:
            sub.addAction(str(job.error)).setEnabled(False)
        sub.addSeparator()
        sub.addAction("Settings…").triggered.connect(lambda: self.showSettings(view))

    # --- scripts --------------------------------------------------------

    def _install_script(self, app):
        scripts = app.webProfile().scripts()
        for script in scripts.find(_SCRIPT_NAME):
            scripts.remove(script)
        script = QWebEngineScript()
        script.setName(_SCRIPT_NAME)
        script.setSourceCode(self._fill_js)
        script.setWorldId(SAFE_WORLD)
        script.setInjectionPoint(QWebEngineScript.InjectionPoint.DocumentReady)
        script.setRunsOnSubFrames(True)
        scripts.insert(script)

    def _inject_into_open_pages(self):
        # Enabled at runtime: pages already open won't run the profile script
        # until they navigate. fill.js is idempotent, so just run it there.
        views = web_views()
        for view in views:
            try:
                for frame in frames_of(view.page()):
                    if is_web(frame.url()):
                        frame.runJavaScript(self._fill_js, SAFE_WORLD)
            except RuntimeError:
                continue
