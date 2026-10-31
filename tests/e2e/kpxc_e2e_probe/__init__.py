# Test-only Falkon plugin for tests/e2e/run.py. Exposes Falkon's own
# PasswordManager/AutoFill calls to the page's SafeJsWorld (as
# window.external.extra.kpxcprobe), so the driver exercises the real
# Falkon -> backend path over CDP. Never install this in a real profile.

import json
import sys

import Falkon
from PySide6 import QtCore
from PySide6.QtCore import QByteArray, QObject, QUrl, Slot
from PySide6.QtWidgets import QLabel, QMenu


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
        _kpxc().fill_menu(self._menu, _current_view())
        return json.dumps([a.text() for a in self._menu.actions() if not a.isSeparator()])

    @Slot(int, result=bool)
    def triggerMenu(self, index):
        self._menu.actions()[index].trigger()
        return True


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
