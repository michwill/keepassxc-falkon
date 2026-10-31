from PySide6.QtCore import QPoint, QRect
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import QMenu

from keepassxc_falkon.widgets import SubMenu


def _menu_at_right_edge():
    screen = QGuiApplication.primaryScreen().availableGeometry()
    parent = QMenu()
    parent.addAction("alice@example.com \u2014 Example")
    sub = SubMenu("Fill", parent)
    for text in ("Fill", "Copy username", "Copy password"):
        sub.addAction(text)
    parent.addMenu(sub)
    parent.popup(QPoint(screen.right() - parent.sizeHint().width(), screen.top() + 10))
    return screen, parent, sub


def test_submenu_left_hanging_off_the_right_edge_moves_left_of_its_menu(qapp):
    screen, parent, sub = _menu_at_right_edge()
    # Where Qt left it on the user's desktop: past the right edge.
    sub.setGeometry(QRect(QPoint(parent.geometry().right() + 1, parent.geometry().top()), sub.sizeHint()))
    assert sub.geometry().right() > screen.right()
    sub.show()
    assert sub.geometry().right() <= screen.right()
    assert sub.geometry().right() < parent.geometry().left()
    sub.close()
    parent.close()


def test_submenu_that_fits_stays_put(qapp):
    screen, parent, sub = _menu_at_right_edge()
    spot = QRect(QPoint(screen.left() + 10, screen.top() + 10), sub.sizeHint())
    sub.setGeometry(spot)
    sub.show()
    assert sub.geometry() == spot
    sub.close()
    parent.close()
