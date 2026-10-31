# KeePassXC for Falkon — use KeePassXC as Falkon's password manager.
#
#   protocol.py  KeePassXC browser-integration protocol over its local socket
#   backend.py   a Falkon PasswordBackend ("KeePassXC" in Preferences → Passwords)
#   filler.py    pushes credentials into pages; fill.js finds the login fields
#   settings.py  status / connection / options dialog
#   plugin.py    the plugin object Falkon loads
#
# Licensed MIT (see LICENSE).

# Falkon imports this package to load the plugin, with its embedded "Falkon"
# module available. Imported anywhere else (the tests), only the Qt-only
# modules (protocol, sodium, store) are usable and nothing is registered.
try:
    import Falkon
except ModuleNotFoundError:
    pass
else:
    from .plugin import KeePassXCPlugin

    plugin = KeePassXCPlugin()
    Falkon.registerPlugin(plugin)
