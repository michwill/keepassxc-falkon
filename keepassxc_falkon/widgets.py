"""Small Qt widgets for the plugin's menus (no Falkon dependency)."""

from PySide6.QtGui import QGuiApplication, QShowEvent
from PySide6.QtWidgets import QMenu


class SubMenu(QMenu):
    """A submenu that never hangs off the screen edge.

    Qt opens a submenu that doesn't fit to the right of its menu on the
    left instead. For the toolbar menu that didn't always happen: on a
    3840x2400 X11 desktop at QT_SCALE_FACTOR=2, half of the submenu went
    past the right edge, while Falkon's own menus flipped fine. So once Qt
    has placed it (show events arrive before the window is mapped), check
    it against the screen its menu is on and move it to the menu's left if
    it sticks out.
    """

    def showEvent(self, event: QShowEvent) -> None:
        super().showEvent(event)
        parent = self.parentWidget()
        if not isinstance(parent, QMenu):
            return
        menu = parent.geometry()
        screen = QGuiApplication.screenAt(menu.center()) or parent.screen()
        bounds = screen.availableGeometry()
        geo = self.geometry()
        if geo.right() > bounds.right():
            self.move(max(bounds.left(), menu.left() - geo.width()), geo.top())
