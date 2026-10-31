"""The plugin's settings dialog (Preferences → Extensions, or the backend's
settings button under Preferences → Passwords)."""

import Falkon
import shiboken6
from PySide6.QtCore import Qt
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import (
    QCheckBox, QDialog, QDialogButtonBox, QGridLayout, QGroupBox, QHBoxLayout,
    QLabel, QPushButton, QVBoxLayout,
)

from .backend import BACKEND_ID

ICON_SIZE = 16


def _icon(ok):
    if ok is None:
        name = "dialog-question"
    else:
        name = "dialog-ok-apply" if ok else "dialog-warning"
    return QIcon.fromTheme(name).pixmap(ICON_SIZE, ICON_SIZE)


class SettingsDialog(QDialog):
    def __init__(self, client, store, parent=None):
        super().__init__(parent)
        self._client = client
        self._store = store
        self.setWindowTitle("KeePassXC")
        self.setWindowIcon(QIcon.fromTheme("keepassxc"))

        status = QGroupBox("Status")
        grid = QGridLayout(status)
        self._rows = {}
        for i, key in enumerate(("running", "database", "connection", "backend")):
            icon, text = QLabel(), QLabel()
            text.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            grid.addWidget(icon, i, 0)
            grid.addWidget(text, i, 1)
            self._rows[key] = (icon, text)
        grid.setColumnStretch(1, 1)

        self._connect = QPushButton("Connect to database…")
        self._connect.clicked.connect(lambda: client.associate(callback=self._refresh))
        self._unlock = QPushButton("Unlock database")
        self._unlock.clicked.connect(lambda: client.unlock())
        self._use = QPushButton("Use KeePassXC for passwords")
        self._use.clicked.connect(self._use_backend)
        refresh = QPushButton("Refresh")
        refresh.clicked.connect(self._refresh)
        actions = QHBoxLayout()
        for button in (self._connect, self._unlock, self._use, refresh):
            actions.addWidget(button)
        actions.addStretch(1)

        options = QGroupBox("Options")
        opt = QVBoxLayout(options)
        self._unlock_opt = QCheckBox("Ask KeePassXC to unlock when a page shows a login form")
        self._unlock_opt.setChecked(store.option("unlock_on_login_form"))
        self._unlock_opt.toggled.connect(lambda on: store.set_option("unlock_on_login_form", on))
        self._many_opt = QCheckBox("When several entries match, fill the best match without asking")
        self._many_opt.setChecked(store.option("fill_first_of_many"))
        self._many_opt.toggled.connect(lambda on: store.set_option("fill_first_of_many", on))
        note = QLabel("Filling on page load follows Falkon's \"Autocomplete passwords\" setting. "
                      "With several matches, pick an account from the key icon in the address bar "
                      "or from the right-click menu of a login field.")
        note.setWordWrap(True)
        for w in (self._unlock_opt, self._many_opt, note):
            opt.addWidget(w)

        forget_row = QHBoxLayout()
        self._saved = QLabel()
        self._saved.setWordWrap(True)
        forget = QPushButton("Forget connections")
        forget.clicked.connect(self._forget)
        forget_row.addWidget(self._saved, 1)
        forget_row.addWidget(forget)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addWidget(status)
        layout.addLayout(actions)
        layout.addWidget(options)
        layout.addLayout(forget_row)
        layout.addWidget(buttons)

        client.stateChanged.connect(self._render)
        self._render()
        self._refresh()

    def done(self, result):
        self._client.stateChanged.disconnect(self._render)
        super().done(result)

    def _refresh(self, *_):
        self._client.status(callback=lambda _job: self._render())

    def _set(self, key, ok, text):
        icon, label = self._rows[key]
        icon.setPixmap(_icon(ok))
        label.setText(text)

    def _render(self):
        c = self._client
        if c.running is None:
            self._set("running", None, "KeePassXC: checking…")
        elif c.running:
            self._set("running", True, "KeePassXC is running")
        else:
            self._set("running", False, "KeePassXC isn't running, or its browser integration is off "
                                        "(KeePassXC → Settings → Browser Integration)")

        if not c.running or c.locked is None:
            self._set("database", None, "Database: unknown")
        elif c.locked:
            self._set("database", False, "Database is locked")
        else:
            self._set("database", True, "Database is unlocked")

        if c.associated:
            self._set("connection", True, f"Connected as “{c.associated_id}”")
        elif c.running and c.locked is False:
            self._set("connection", False, "Not connected to the open database")
        else:
            self._set("connection", None, "Connection: unknown")

        active = self._active_backend()
        is_ours = active == BACKEND_ID
        self._set("backend", is_ours, "Falkon stores passwords in KeePassXC" if is_ours
                  else "Falkon's password backend is not KeePassXC")

        self._connect.setEnabled(bool(c.running) and not c.associated)
        self._unlock.setEnabled(bool(c.running) and c.locked is not False)
        self._use.setVisible(not is_ours)
        count = len(self._store.associations())
        self._saved.setText(f"Saved database connections: {count}")

    def _password_manager(self):
        return Falkon.MainApplication.instance().autoFill().passwordManager()

    def _active_backend(self):
        pm = self._password_manager()
        active = shiboken6.getCppPointer(pm.activeBackend())[0]
        for backend_id, backend in pm.availableBackends().items():
            if shiboken6.getCppPointer(backend)[0] == active:
                return backend_id
        return None

    def _use_backend(self):
        self._password_manager().switchBackend(BACKEND_ID)
        self._render()

    def _forget(self):
        self._client.forget_associations()
        self._render()
