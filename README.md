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
  account from the **KeePassXC toolbar button**, the **key icon** in the
  address bar, or **right-click a login field → KeePassXC** (works inside
  iframes too).
- **Keyboard: Ctrl+Shift+U** fills the login form in the current tab. With a
  single matching entry it fills straight away. With several, the accounts
  pop up under the focused field, the first one highlighted, so Enter or the
  arrow keys finish the job. If the database is locked or not connected, the
  popup offers to unlock or connect. Change or turn off the shortcut in the
  plugin settings.
- **Toolbar button** on the navigation bar: the badge shows how many entries
  match the current tab, and the icon dims when KeePassXC is locked, not
  running or not connected. Its menu lists the entries per site: the page
  itself, plus any login iframe on another site. Each entry offers **Fill**,
  **Copy username**, **Copy password** and, if the entry has one,
  **Copy TOTP** (a fresh code from KeePassXC). Copied passwords and codes are
  marked so clipboard managers skip them, and are cleared after 10 seconds
  (configurable).
- **Saves and updates** through Falkon's own *Remember / Update* bar. New
  logins go to KeePassXC's "KeePassXC-Browser Passwords" group; an existing
  entry with the same username is updated instead of duplicated.
- **Locked database:** when a page shows a login form, KeePassXC is asked to
  show its unlock dialog (throttled; can be turned off). Once you unlock, the
  open pages are filled. A save made while locked is kept and written after
  you unlock.
- **Passkeys:** sites' passkey (WebAuthn) requests are answered by KeePassXC
  (2.7.7+). Creating a passkey stores it in KeePassXC's "KeePassXC-Browser
  Passkeys" group; signing in shows KeePassXC's confirmation dialog. Falkon
  itself has no passkey support: without this, passkey sign-in just hangs.
  Works on `https://` sites in the page itself and same-site frames. If the
  database is locked, KeePassXC asks you to unlock it and the sign-in carries
  on. Can be turned off in the plugin settings.
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
2. *Preferences → Extensions*: tick **KeePassXC**. Its toolbar button is
   added to the navigation bar the first time (from the next window or
   restart if you enable it mid-session; move or remove it with *Configure
   Toolbar*).
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
- `menus.py` — the toolbar button and the field context menu.
- `passkeys.js` + `passkeys.py` — passkeys. `passkeys.js` runs in the page's
  own JavaScript world, before the site's scripts. It stands in for
  `navigator.credentials.create/get` (passkey requests only), serializes them,
  and turns KeePassXC's answer back into `PublicKeyCredential` objects. It
  holds no secrets. Requests reach Python through `fill.js`. Python probes for
  the frame that really has that request pending, takes the origin from
  Chromium, and refuses frames from another site (KeePassXC signs with
  `"crossOrigin": false`). KeePassXC then checks the relying-party ID against
  that origin and asks you.
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
- No HTTP basic-auth prefill, TOTP autofill or password generator yet (TOTP
  codes can be copied from the toolbar menu).
- Passkeys: no "conditional" sign-in (passkeys offered in a login field's
  autofill dropdown). The plugin reports it unavailable, so sites show their
  regular "Sign in with a passkey" button. Not available in frames embedded
  from another site. Turning passkeys on or off applies to pages loaded
  afterwards. Hardware security keys don't work in Falkon either way (it has
  no WebAuthn dialogs).
- After updating the plugin, restart Falkon (modules are cached).
- **A KeePassXC bug to know about (2.8):** a change that arrives over browser
  integration *while KeePassXC is saving* stays in memory but is never
  written. KeePassXC marks the database clean when the save returns, so the
  change is lost at the next lock or quit, without a "save changes?" prompt.
  The plugin spaces its own changes 3 seconds apart, so a passkey registered
  right after a saved password can't hit this. Changes made at the same moment
  in KeePassXC itself, or by another client, still can.

## Development

```bash
uv venv --system-site-packages     # PySide6 comes from the system, as in Falkon
uv pip install pytest ruff mypy ty pykeepass websocket-client cryptography
./check.sh                         # ruff, mypy, ty, unit tests (fake KeePassXC)
./check.sh --e2e                   # … plus real Falkon + real KeePassXC, sandboxed
```

The package is type-checked strictly (every function annotated, mypy and
ty). `stubs/Falkon.pyi` types the part of Falkon's PyFalkon API the plugin
uses, against the PySide6 classes it derives from. Ruff runs a broad rule set
(bugbear, simplify, pyupgrade, pytest style, …); see `pyproject.toml`.

The end-to-end run builds a throwaway KeePassXC database and Falkon profile
and runs both apps inside a bubblewrap sandbox, sealed off from your desktop
session:

- its own network namespace, so no abstract sockets, including your X
  server's;
- a private `/tmp` and `/run`: no access to your X server, session or system
  D-Bus (so no Polkit prompts) or KeePassXC socket;
- your filesystem read-only, a cleared environment and a fake `HOME`.

Inside, KeePassXC runs on a private Xvfb display (the test presses keys in
its dialogs) with Quick Unlock off, and Falkon runs offscreen. Falkon is
driven over the DevTools protocol, with a small test-only plugin
(`tests/e2e/kpxc_e2e_probe`) exposing Falkon's password manager. Passkeys are
verified the way a website's server would: client data, authenticator data
and the signature. It needs `bwrap`, `Xvfb`, `dbus-run-session` and
`libXtst`.

Set `KEEPASSXC_FALKON_DEBUG=1` before starting Falkon to log the plugin's
activity to stderr.

## License

GPL-3.0-or-later.
