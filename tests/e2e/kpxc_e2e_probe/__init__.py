# Test-only Falkon plugin for tests/e2e/run.py. Exposes Falkon's own
# PasswordManager/AutoFill calls to the page's SafeJsWorld (as
# window.external.extra.kpxcprobe), so the driver exercises the real
# Falkon -> backend path over CDP. Never install this in a real profile.

import json
import sys

import Falkon
from PySide6 import QtCore
from PySide6.QtCore import QByteArray, QObject, QUrl, Slot
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import QLabel, QMenu, QWidget


def _autofill():
    return Falkon.MainApplication.instance().autoFill()


class Probe(QObject):
    @Slot(result=str)
    def activeBackend(self):
        return _autofill().passwordManager().activeBackend().name()

    @Slot(str, result=str)
    def entries(self, url):
        entries = _autofill().passwordManager().getEntries(QUrl(url))
        return json.dumps([{"id": e.id, "host": e.host, "username": e.username, "password": e.password}
                           for e in entries])

    @Slot(str, result=str)
    def usernames(self, url):
        return json.dumps(list(_autofill().passwordManager().getUsernames(QUrl(url))))

    @Slot(str, str, str, result=bool)
    def addEntry(self, url, username, password):
        data = Falkon.PageFormData()
        data.username = username
        data.password = password
        data.postData = QByteArray()
        _autofill().addEntry(QUrl(url), data)
        return True

    @Slot(str, str, str, result=bool)
    def updatePassword(self, url, username, password):
        for entry in _autofill().getFormData(QUrl(url)):
            if entry.username == username:
                entry.password = password
                return _autofill().updateEntry(entry)
        return False


def _kpxc():
    return sys.modules["keepassxc_falkon"].plugin


def _current_view():
    return Falkon.MainApplication.instance().getWindow().weView()


class UiProbe(QObject):
    """Drives the plugin's own UI code (dialog, context menu) headlessly."""

    @Slot(result=str)
    def settingsTexts(self):
        from keepassxc_falkon.settings import SettingsDialog
        plugin = _kpxc()
        dialog = SettingsDialog(plugin.client, plugin.store)
        texts = [label.text() for label in dialog.findChildren(QLabel) if label.text()]
        self._dialog = dialog      # status probe answers asynchronously
        return json.dumps(texts)

    @Slot(result=str)
    def settingsTextsNow(self):
        texts = [label.text() for label in self._dialog.findChildren(QLabel) if label.text()]
        return json.dumps(texts)

    @Slot(result=str)
    def menuLabels(self):
        self._menu = QMenu()
        _kpxc().entries_menu.populate(self._menu, _current_view(), direct_fill=True)
        return json.dumps([a.text() for a in self._menu.actions() if not a.isSeparator()])

    @Slot(int, result=bool)
    def triggerMenu(self, index):
        self._menu.actions()[index].trigger()
        return True

    @Slot(result=str)
    def toolbarMenu(self):
        self._tmenu = QMenu()
        _kpxc().entries_menu.populate(self._tmenu, _current_view(), direct_fill=False)
        return json.dumps([{"text": a.text(), "enabled": a.isEnabled(),
                            "sub": [b.text() for b in a.menu().actions()] if a.menu() else None}
                           for a in self._tmenu.actions() if not a.isSeparator()])

    @Slot(str, str, result=bool)
    def triggerToolbar(self, entry, action):
        for a in self._tmenu.actions():
            if a.text() == entry:
                for b in a.menu().actions():
                    if b.text() == action:
                        b.trigger()
                        return True
        return False

    @Slot(result=str)
    def clipboard(self):
        mime = QGuiApplication.clipboard().mimeData()
        return json.dumps({"text": mime.text() if mime else "",
                           "secret": bool(mime and mime.hasFormat("x-kde-passwordManagerHint"))})

    @Slot(str, int, result=bool)
    def setOption(self, name, value):
        _kpxc().store.set_option(name, value)
        return True

    @Slot(result=str)
    def button(self):
        button = next(iter(_kpxc()._buttons.values()))
        button.refresh()
        window = Falkon.MainApplication.instance().getWindow()
        shown = any(w.property("button-id") == button.id() and w.isVisible()
                    for w in window.findChildren(QWidget))
        return json.dumps({"badge": button.badgeText(), "tip": button.toolTip(), "shown": shown})


class ProbePlugin(Falkon.PluginInterface, QtCore.QObject):
    def init(self, state, settingsPath):
        self.probe = Probe(self)
        self.ui = UiProbe(self)
        Falkon.ExternalJsObject.registerExtraObject("kpxcprobe", self.probe)
        Falkon.ExternalJsObject.registerExtraObject("kpxcui", self.ui)

    def unload(self):
        Falkon.ExternalJsObject.unregisterExtraObject(self.probe)
        Falkon.ExternalJsObject.unregisterExtraObject(self.ui)

    def testPlugin(self):
        return True


Falkon.registerPlugin(ProbePlugin())
