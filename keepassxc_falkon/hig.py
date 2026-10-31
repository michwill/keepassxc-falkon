"""GNOME 2 HIG-style layout for the plugin's dialogs.

Spacing is set explicitly, derived from the font, instead of coming from the
widget style: some themes (Kvantum's DoorMaker, for one) set layout margins
and spacing to 2 px, which crams any dialog that relies on them. The rhythm
follows the GNOME 2 HIG, scaled to the font:

- a border of half a line-height around the dialog,
- a third of a line-height between related rows ("within a paragraph"),
- twice that between sections and above the button row,
- sections headed by a bold label with their content indented, rather than
  framed group boxes.
"""

from PySide6.QtWidgets import QBoxLayout, QLabel, QVBoxLayout, QWidget


def item_spacing(widget: QWidget) -> int:
    """Gap between related rows within a section."""
    return max(2, widget.fontMetrics().height() // 3)


def group_spacing(widget: QWidget) -> int:
    """Gap between sections, and above a dialog's button row."""
    return 2 * item_spacing(widget)


def dialog_margin(widget: QWidget) -> int:
    """Border between the dialog's edge and its content."""
    return widget.fontMetrics().height() // 2


def apply_dialog_layout(dialog: QWidget, layout: QBoxLayout) -> None:
    """The dialog's top-level layout: HIG border, sections spaced apart."""
    margin = dialog_margin(dialog)
    layout.setContentsMargins(margin, margin, margin, margin)
    layout.setSpacing(group_spacing(dialog))


def section(parent: QWidget, title: str) -> tuple[QVBoxLayout, QVBoxLayout]:
    """A section: a bold heading over indented content. Returns
    ``(section_layout, body)``; add the section layout to the dialog's
    layout and the section's widgets to ``body``."""
    heading = QLabel(title)
    font = heading.font()
    font.setBold(True)
    heading.setFont(font)
    outer = QVBoxLayout()
    outer.setContentsMargins(0, 0, 0, 0)
    outer.setSpacing(item_spacing(parent))
    outer.addWidget(heading)
    body = QVBoxLayout()
    body.setContentsMargins(group_spacing(parent), 0, 0, 0)
    body.setSpacing(item_spacing(parent))
    outer.addLayout(body)
    return outer, body
