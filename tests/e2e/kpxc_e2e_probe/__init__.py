# Test-only Falkon plugin for tests/e2e/run.py. Exposes Falkon's own
# PasswordManager/AutoFill calls to the page's SafeJsWorld (as
# window.external.extra.kpxcprobe), so the driver exercises the real
# Falkon -> backend path over CDP. Never install this in a real profile.

import json
import sys
from typing import Any

import Falkon
from PySide6 import QtCore
from PySide6.QtCore import QByteArray, QObject, Qt, QUrl, Slot
from PySide6.QtGui import QGuiApplication
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QLabel, QMenu, QWidget


def _autofill():
    return Falkon.MainApplication.instance().autoFill()


class Probe(QObject):
    @Slot(result=str)
    def activeBackend(self):
        return _autofill().passwordManager().activeBackend().name()

    @Slot(str, result=str)
    def entries(self, url):
        entries = _autofill().passwordManager().getEntries(QUrl(url))
        return json.dumps(
            [{"id": e.id, "host": e.host, "username": e.username, "password": e.password} for e in entries]
        )

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


def _window():
    window = Falkon.MainApplication.instance().getWindow()
    assert window is not None
    return window


def _current_view():
    return _window().weView()


def _describe(action):
    if action.isSeparator():
        return "-"
    marks = ("~" if not action.isEnabled() else "") + ("*" if action.font().bold() else "")
    return marks + action.text()


class UiProbe(QObject):
    """Drives the plugin's own UI code (dialog, context menu) headlessly."""

    @Slot(result=str)
    def settingsTexts(self):
        from keepassxc_falkon.settings import SettingsDialog

        plugin = _kpxc()
        dialog = SettingsDialog(plugin.client, plugin.store)
        texts = [label.text() for label in dialog.findChildren(QLabel) if label.text()]
        self._dialog = dialog  # status probe answers asynchronously
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
        """The toolbar menu's items, "-" for a separator; "*" marks a bold
        (an entry's fill) item, "~" a disabled one."""
        self._tmenu = QMenu()
        _kpxc().entries_menu.populate(self._tmenu, _current_view(), direct_fill=False)
        return json.dumps([_describe(a) for a in self._tmenu.actions()])

    @Slot(str, str, result=bool)
    def triggerToolbar(self, entry, action):
        """Trigger ``action`` of the toolbar menu's ``entry``: "Fill" is the
        entry itself, the copy actions follow it up to the next separator."""
        actions = self._tmenu.actions()
        start = next(i for i, a in enumerate(actions) if a.text() == entry)
        if action == "Fill":
            actions[start].trigger()
            return True
        for a in actions[start + 1 :]:
            if a.isSeparator():
                break
            if a.text() == action:
                a.trigger()
                return True
        return False

    @Slot(result=str)
    def clipboard(self):
        mime = QGuiApplication.clipboard().mimeData()
        return json.dumps(
            {"text": mime.text() if mime else "", "secret": bool(mime and mime.hasFormat("x-kde-passwordManagerHint"))}
        )

    @Slot(str, int, result=bool)
    def setOption(self, name, value):
        _kpxc().store.set_option(name, value)
        return True

    @Slot(result=bool)
    def pressFillShortcut(self):
        """A real Ctrl+Shift+U through Qt's shortcut handling (CDP key events
        go straight to Chromium and never reach Qt's shortcuts)."""
        window = _window()
        window.activateWindow()
        target = QApplication.focusWidget() or window.weView()
        QTest.keyClick(target, Qt.Key.Key_U, Qt.KeyboardModifier.ControlModifier | Qt.KeyboardModifier.ShiftModifier)
        return True

    @Slot(result=str)
    def popup(self):
        menu = QApplication.activePopupWidget()
        if not isinstance(menu, QMenu):
            return json.dumps(None)
        view = _current_view()
        where = view.mapFromGlobal(menu.pos())
        active = menu.activeAction()
        return json.dumps(
            {
                "labels": [a.text() for a in menu.actions() if not a.isSeparator()],
                "active": active.text() if active else None,
                "at": [where.x(), where.y()],
                "view": [view.width(), view.height()],
            }
        )

    @Slot(result=bool)
    def triggerPopupActive(self):
        menu = QApplication.activePopupWidget()
        assert isinstance(menu, QMenu)
        action = menu.activeAction()
        menu.close()
        action.trigger()
        return True

    @Slot(str, result=str)
    def toolbarMenuGeometry(self, grab_to):
        """Maximize the window, click the KeePassXC toolbar button; report
        where the menu went and whether it has submenus. With ``grab_to``,
        also save a picture of the menu there."""
        window = _window()
        window.showMaximized()
        QTest.qWait(1000)
        avail = window.screen().availableGeometry()
        button = next(w for w in window.findChildren(QWidget) if w.property("button-id") == "keepassxc-falkon")
        QTest.mouseClick(button, Qt.MouseButton.LeftButton)
        QTest.qWait(300)
        menu = QApplication.activePopupWidget()
        assert isinstance(menu, QMenu)
        if grab_to:
            menu.grab().save(grab_to)
        result = {
            "screen": avail.getRect(),
            "menu": menu.geometry().getRect(),
            "submenus": [a.text() for a in menu.actions() if a.menu() is not None],
        }
        menu.close()
        return json.dumps(result)

    @Slot(int, result=bool)
    def setCacheTtl(self, seconds):
        # The plugin's module as Falkon loaded it (importing it here could load it twice).
        protocol: Any = sys.modules["keepassxc_falkon.protocol"]
        protocol.CACHE_TTL_S = seconds
        return True

    @Slot(result=str)
    def button(self):
        button = next(iter(_kpxc()._buttons.values()))
        button.refresh()
        shown = any(w.property("button-id") == button.id() and w.isVisible() for w in _window().findChildren(QWidget))
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
