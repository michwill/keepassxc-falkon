# KeePassXC for Falkon

A Falkon plugin that makes **KeePassXC** Falkon's password manager. It plugs
into Falkon's own password-backend slot (*Preferences → Passwords →
Backend: KeePassXC*), so Falkon's usual password UI — the "save password?"
bar, the key icon in the address bar — works against your KeePassXC
database instead of Falkon's built-in storage.

It talks to KeePassXC the same way the official keepassxc-browser extension
does (KeePassXC's browser-integration protocol, encrypted with libsodium's
`crypto_box`), but directly over KeePassXC's local socket — no proxy, no
browser extension, no extra Python packages.

## What it does

- **Fills logins** when a page loads and exactly one KeePassXC entry matches
  (following Falkon's *Autocomplete passwords* setting). Works with plain
  forms, script-rendered / nameless fields (React and friends), open shadow
  DOM, and login forms inside iframes (each frame gets its own origin's entry).
- **Several matching entries:** nothing is filled automatically. Pick an
  account from the **key icon** in the address bar, or **right-click a login
  field → KeePassXC**.
- **Saves and updates** through Falkon's own *Remember / Update* bar. New
  logins go to KeePassXC's "KeePassXC-Browser Passwords" group; an existing
  entry with the same username is updated instead of duplicated.
- **Locked database:** when a page shows a login form, KeePassXC is asked to
  show its unlock dialog (throttled; can be turned off). Once you unlock, the
  open pages are filled. A save made while locked is kept and written after
  you unlock.
- **Asks KeePassXC only on pages with login fields**, like keepassxc-browser,
  so browsing a site doesn't keep raising KeePassXC's access dialog or hand it
  your history.
- Never deletes anything in KeePassXC. Falkon's *Preferences → Passwords* list
  stays empty with this backend; manage entries in KeePassXC.

## Requirements

- Falkon with Python plugin support (PyFalkon / PySide6; KDE's packages have
  it). Developed against Falkon 26.04 and Qt 6.11; needs Qt ≥ 6.8 for
  per-frame filling.
- KeePassXC 2.7 or newer with **Settings → Browser Integration → Enable
  browser integration** turned on. The per-browser checkboxes (Firefox,
  Chrome, …) don't matter for Falkon.
- libsodium (already a KeePassXC dependency on most distributions).

## Install

Falkon loads Python plugins from `~/.config/falkon/plugins/`. Link (or copy)
the `keepassxc_falkon` directory there:

```bash
mkdir -p ~/.config/falkon/plugins
ln -s "$PWD/keepassxc_falkon" ~/.config/falkon/plugins/keepassxc_falkon
```

Then:

1. Restart Falkon completely (it caches Python modules for the whole session,
   and it's single-instance, so make sure no `falkon` process is left).
2. *Preferences → Extensions*: tick **KeePassXC**.
3. *Preferences → Passwords*: set **Backend** to **KeePassXC**.
4. KeePassXC asks you to name the new connection (e.g. `falkon-laptop`).
   That's the one-time association, the same as for keepassxc-browser.

The plugin's settings (Preferences → Extensions → KeePassXC → Settings, or the
backend's settings button) show the connection status and let you connect,
unlock, or forget connections.

KeePassXC asks before giving Falkon a site's passwords for the first time; tick
*Remember* in that dialog, or enable *Never ask before accessing credentials*
in KeePassXC's browser-integration settings.

## How it works

```
 page frame (SafeJsWorld)          Falkon / Python                    KeePassXC
 ┌───────────────────────┐  hint   ┌──────────────────────────┐  socket  ┌─────────┐
 │ fill.js finds login   │ ──────▶ │ Filler: finds the frame  │ ───────▶ │ browser │
 │ fields, holds a token │         │ by its real URL, looks   │ ◀─────── │ server  │
 │                       │ ◀────── │ up creds, pushes a fill  │ crypto_  │         │
 └───────────────────────┘  fill   │ PasswordBackend for      │   box    └─────────┘
                                   │ Falkon's own save/lookup │
                                   └──────────────────────────┘
```

- `keepassxc_falkon/protocol.py` — the KeePassXC protocol client: key
  exchange, association, `get-logins`, `set-login`, lock/unlock events.
  Requests are serialized, so replies can never be confused (KeePassXC's error
  replies carry no nonce, and its dialogs can delay a reply). Falkon queries
  password backends synchronously, so the client can also block briefly on the
  socket. That uses `waitForReadyRead`, not a nested event loop, so nothing
  re-enters Falkon while it waits.
- `backend.py` — the Falkon `PasswordBackend`.
- `filler.py` + `fill.js` — filling. Falkon's own autofill replays a stored
  form submission by input `name`, which KeePassXC entries don't have, so the
  plugin fills by itself. `fill.js` runs in Falkon's isolated JavaScript world
  (page scripts can't see it) and only *reports* that a frame has login fields.
  The plugin then looks credentials up for the URL Chromium reports for that
  frame, not for whatever the page claims, and fills only the document holding
  the reporting token. QtWebEngine gives only the top frame a channel to
  Python, so iframes relay their report through the top frame. The report is
  still just a hint, for the same reason.
- `sodium.py` — `crypto_box` through ctypes (libsodium), so nothing has to be
  installed into Falkon's Python.
- `store.py` — the association keys, in
  `<falkon profile>/extensions/keepassxc.json` (mode 0600).

## Limitations

- Falkon offers to save only logins submitted through a `<form>` in the top
  frame (that's Falkon's own form watcher). Form-less logins and logins inside
  iframes are filled, but you have to add them to KeePassXC yourself.
- No HTTP basic-auth prefill, TOTP, passkeys or password generator yet.
- After updating the plugin, restart Falkon (modules are cached).

## Development

```bash
uv venv --system-site-packages     # PySide6 comes from the system, as in Falkon
uv pip install pytest pykeepass websocket-client
.venv/bin/python -m pytest         # unit tests against a fake KeePassXC
.venv/bin/python tests/e2e/run.py  # real Falkon + real KeePassXC, isolated
```

The end-to-end run builds a throwaway KeePassXC database and Falkon profile
and starts both apps headless (offscreen Qt, private `HOME`/`XDG_*`/`TMPDIR`,
a private runtime dir for KeePassXC's socket, a private D-Bus session). It
never touches your own KeePassXC, Falkon profile or desktop. It drives Falkon
over the DevTools protocol, with a small test-only plugin
(`tests/e2e/kpxc_e2e_probe`) exposing Falkon's password manager.

Set `KEEPASSXC_FALKON_DEBUG=1` before starting Falkon to log the plugin's
activity to stderr.

## License

GPL-3.0-or-later.
