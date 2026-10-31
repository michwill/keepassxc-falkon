"""Press keys in a window on an X display (for KeePassXC's dialogs in the
e2e run): find a top-level window by title, focus it, send a key via XTest.
ctypes over libX11/libXtst, so no extra packages."""

import ctypes
import time

_x11 = ctypes.CDLL("libX11.so.6")
_xtst = ctypes.CDLL("libXtst.so.6")

Window = ctypes.c_ulong
_x11.XOpenDisplay.restype = ctypes.c_void_p
_x11.XOpenDisplay.argtypes = [ctypes.c_char_p]
_x11.XCloseDisplay.argtypes = [ctypes.c_void_p]
_x11.XDefaultRootWindow.restype = Window
_x11.XDefaultRootWindow.argtypes = [ctypes.c_void_p]
_x11.XQueryTree.argtypes = [ctypes.c_void_p, Window, ctypes.POINTER(Window), ctypes.POINTER(Window),
                            ctypes.POINTER(ctypes.POINTER(Window)), ctypes.POINTER(ctypes.c_uint)]
_x11.XFetchName.argtypes = [ctypes.c_void_p, Window, ctypes.POINTER(ctypes.c_char_p)]
_x11.XFree.argtypes = [ctypes.c_void_p]
_x11.XSetInputFocus.argtypes = [ctypes.c_void_p, Window, ctypes.c_int, ctypes.c_ulong]
_x11.XRaiseWindow.argtypes = [ctypes.c_void_p, Window]
_x11.XStringToKeysym.restype = ctypes.c_ulong
_x11.XStringToKeysym.argtypes = [ctypes.c_char_p]
_x11.XKeysymToKeycode.restype = ctypes.c_ubyte
_x11.XKeysymToKeycode.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
_x11.XFlush.argtypes = [ctypes.c_void_p]
_x11.XSync.argtypes = [ctypes.c_void_p, ctypes.c_int]
_xtst.XTestFakeKeyEvent.argtypes = [ctypes.c_void_p, ctypes.c_uint, ctypes.c_int, ctypes.c_ulong]

_REVERT_TO_PARENT = 2
_IS_VIEWABLE = 2


class _WindowAttributes(ctypes.Structure):
    _fields_ = [("x", ctypes.c_int), ("y", ctypes.c_int), ("width", ctypes.c_int), ("height", ctypes.c_int),
                ("border_width", ctypes.c_int), ("depth", ctypes.c_int), ("visual", ctypes.c_void_p),
                ("root", Window), ("class_", ctypes.c_int), ("bit_gravity", ctypes.c_int),
                ("win_gravity", ctypes.c_int), ("backing_store", ctypes.c_int),
                ("backing_planes", ctypes.c_ulong), ("backing_pixel", ctypes.c_ulong),
                ("save_under", ctypes.c_int), ("colormap", ctypes.c_ulong), ("map_installed", ctypes.c_int),
                ("map_state", ctypes.c_int), ("all_event_masks", ctypes.c_long),
                ("your_event_mask", ctypes.c_long), ("do_not_propagate_mask", ctypes.c_long),
                ("override_redirect", ctypes.c_int), ("screen", ctypes.c_void_p)]


_x11.XGetWindowAttributes.argtypes = [ctypes.c_void_p, Window, ctypes.POINTER(_WindowAttributes)]


class XDisplay:
    def __init__(self, name):
        self._dpy = _x11.XOpenDisplay(name.encode())
        if not self._dpy:
            raise RuntimeError(f"can't open X display {name}")

    def close(self):
        _x11.XCloseDisplay(self._dpy)

    def titles(self):
        """Titles of the windows on screen (Qt keeps closed dialogs around unmapped)."""
        return [title for _w, title in self._top_levels()]

    def _top_levels(self):
        root = _x11.XDefaultRootWindow(self._dpy)
        root_ret, parent_ret = Window(), Window()
        children = ctypes.POINTER(Window)()
        count = ctypes.c_uint()
        if not _x11.XQueryTree(self._dpy, root, ctypes.byref(root_ret), ctypes.byref(parent_ret),
                               ctypes.byref(children), ctypes.byref(count)):
            return []
        found = []
        attrs = _WindowAttributes()
        for i in range(count.value):
            if not _x11.XGetWindowAttributes(self._dpy, children[i], ctypes.byref(attrs)) \
                    or attrs.map_state != _IS_VIEWABLE:
                continue
            name = ctypes.c_char_p()
            if _x11.XFetchName(self._dpy, children[i], ctypes.byref(name)) and name.value:
                found.append((children[i], name.value.decode("utf-8", "replace")))
                _x11.XFree(name)
        if children:
            _x11.XFree(children)
        return found

    def press(self, title, *keys, timeout=15.0):
        """Wait for a window titled ``title``, focus it, then type ``keys``
        (each like ``"Return"`` or ``"shift+Tab"``)."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            matches = [w for w, t in self._top_levels() if t == title]
            if matches:
                window = matches[-1]
                time.sleep(0.5)            # let Qt finish mapping and laying out
                _x11.XRaiseWindow(self._dpy, window)
                _x11.XSetInputFocus(self._dpy, window, _REVERT_TO_PARENT, 0)
                _x11.XSync(self._dpy, 0)
                time.sleep(0.3)
                for key in keys:
                    self._type(key)
                    time.sleep(0.2)
                return
            time.sleep(0.2)
        raise AssertionError(f"no window titled {title!r} (have: {self.titles()})")

    def _type(self, combo):
        codes = [_x11.XKeysymToKeycode(self._dpy, _x11.XStringToKeysym(
            {"shift": "Shift_L", "ctrl": "Control_L", "alt": "Alt_L"}.get(part, part).encode()))
            for part in combo.split("+")]
        for code in codes:
            _xtst.XTestFakeKeyEvent(self._dpy, code, 1, 0)
        for code in reversed(codes):
            _xtst.XTestFakeKeyEvent(self._dpy, code, 0, 0)
        _x11.XFlush(self._dpy)

    def type_text(self, title, text, then="Return", timeout=15.0):
        """Type ``text`` (letters, digits, '-') into the window, then ``then``."""
        names = {"-": "minus", "_": "underscore", ".": "period", " ": "space"}
        keys = [("shift+" + c if c.isupper() else c) if c.isalnum() else names[c] for c in text]
        self.press(title, *keys, then, timeout=timeout)
