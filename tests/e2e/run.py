#!/usr/bin/env python3
"""End-to-end test: the plugin inside a real Falkon, talking to a real KeePassXC.

Sealed off from the user's desktop session at the kernel level, not just by
environment variables (KeePassXC, for one, connects to the *system* bus at a
hard-coded path for Polkit "quick unlock", which put a Polkit prompt on the
user's screen before this was sandboxed). Three stages:

1. outer — makes a work dir and starts everything else under bubblewrap:
   its own network namespace (no abstract sockets: not the user's X server
   or buses), private /tmp and /run (no X/D-Bus/KeePassXC sockets, no system
   bus, so no Polkit), the real filesystem read-only, the work dir writable,
   and a cleared environment: fake HOME / XDG_* / TMPDIR plus an allowlist.
2. sandbox — inside bubblewrap: starts a virtual X display (Xvfb) and a
   private D-Bus session.
3. inner — runs the throwaway KeePassXC (on the virtual display, so the test
   can press keys in its dialogs; Quick Unlock off) and Falkon (offscreen),
   and drives them.

    .venv/bin/python tests/e2e/run.py [--workdir DIR] [--keep]

Needs the ``e2e`` dependency group (pykeepass, websocket-client).
"""

import argparse
import base64
import hashlib
import hmac
import http.server
import json
import os
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from typing import Any

import websocket
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_der_public_key
from pykeepass import PyKeePass, create_database

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, REPO)
from keepassxc_falkon import sodium  # noqa: E402
from keepassxc_falkon.webauthn import attested_auth_data  # noqa: E402
from tests.e2e.xkeys import XDisplay  # noqa: E402

DB_PASSWORD = "e2e-password"
ASSOC_ID = "falkon-e2e"
TOTP_SECRET = "JBSWY3DPEHPK3PXP"
PASSKEY_DIALOG = "KeePassXC - Passkey credentials"
# That dialog's default button is Cancel; from its initial focus, Shift+Tab
# wraps round to Register/Authenticate.
CONFIRM = ("shift+Tab", "space")
# Carried into the sandbox; everything else stays behind (see the docstring).
_PASS_ENV = {"PATH", "LANG", "LANGUAGE", "TERM", "USER", "LOGNAME", "SHELL", "TZ"}
_SANDBOX_RUNTIME = "/run/kpxc-e2e"
# Must not exist inside: their presence means the sandbox leaked.
_SESSION_ENV = (
    "WAYLAND_DISPLAY",
    "XAUTHORITY",
    "SESSION_MANAGER",
    "SSH_AUTH_SOCK",
    "XDG_SESSION_ID",
    "XDG_CURRENT_DESKTOP",
    "KDE_FULL_SESSION",
    "GNOME_KEYRING_CONTROL",
    "GPG_AGENT_INFO",
)

PAGES = {
    "/classic": """<!doctype html><title>classic</title>
<form action="/submit" method="post">
  <input name="user" type="text"><input name="pass" type="password"><button>Sign in</button>
</form>""",
    # Nameless inputs, no <form>, rendered late, page-world listeners (React-ish).
    "/spa": """<!doctype html><title>spa</title><div id="app"></div><script>
window.__events = 0;
setTimeout(function () {
  var app = document.getElementById('app');
  var u = document.createElement('input'); u.autocomplete = 'username';
  var p = document.createElement('input'); p.type = 'password';
  [u, p].forEach(function (el) {
    el.addEventListener('input', function () { window.__events++; });
    app.appendChild(el);
  });
}, 1200);
</script>""",
    "/shadow": """<!doctype html><title>shadow</title><x-login></x-login><script>
customElements.define('x-login', class extends HTMLElement {
  constructor() { super(); this.attachShadow({mode: 'open'}).innerHTML =
    '<form><input type="email" name="email"><input type="password" name="pw"></form>'; }
});
</script>""",
    "/signup": """<!doctype html><title>signup</title><form>
  <input type="email" name="email" autocomplete="email">
  <input type="password" name="pw" autocomplete="new-password">
  <input type="password" name="pw2" autocomplete="new-password">
</form>""",
    # A minimal relying party: the test drives startRegister/startLogin and
    # verifies what comes back in Python, as a site's server would.
    "/passkey": """<!doctype html><title>passkey</title><script>
function b64u(buf) {
  var b = new Uint8Array(buf), s = "";
  for (var i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
  return btoa(s).replace(/\\+/g, "-").replace(/\\//g, "_").replace(/=+$/, "");
}
function unb64u(t) {
  t = t.replace(/-/g, "+").replace(/_/g, "/"); while (t.length % 4) t += "=";
  var s = atob(t), out = new Uint8Array(s.length);
  for (var i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}
window.rp = {};
window.startRegister = function (exclude, rpName) {
  var challenge = crypto.getRandomValues(new Uint8Array(32));
  var userId = crypto.getRandomValues(new Uint8Array(16));
  rp.regChallenge = b64u(challenge); rp.userId = b64u(userId); rp.reg = null;
  navigator.credentials.create({publicKey: {
    challenge: challenge, rp: {name: rpName || "E2E RP", id: "localhost"},
    user: {id: userId, name: "erin@localhost", displayName: "Erin"},
    pubKeyCredParams: [{type: "public-key", alg: -7}],
    excludeCredentials: exclude ? [{type: "public-key", id: unb64u(exclude)}] : [],
    authenticatorSelection: {residentKey: "required", userVerification: "preferred"},
    timeout: 60000}}).then(function (c) {
      rp.reg = {ok: true, instance: c instanceof PublicKeyCredential,
                responseInstance: c.response instanceof AuthenticatorAttestationResponse,
                id: c.id, rawIdMatches: b64u(c.rawId) === c.id, json: c.toJSON(),
                publicKey: b64u(c.response.getPublicKey()), alg: c.response.getPublicKeyAlgorithm(),
                authenticatorData: b64u(c.response.getAuthenticatorData()),
                transports: c.response.getTransports(), extensions: c.getClientExtensionResults()};
    }, function (e) { rp.reg = {ok: false, name: e.name, message: e.message}; });
};
window.startLogin = function (allow) {
  var challenge = crypto.getRandomValues(new Uint8Array(32));
  rp.loginChallenge = b64u(challenge); rp.login = null;
  navigator.credentials.get({publicKey: {
    challenge: challenge, rpId: "localhost", userVerification: "preferred", timeout: 60000,
    allowCredentials: allow ? [{type: "public-key", id: unb64u(allow)}] : []}}).then(function (c) {
      rp.login = {ok: true, instance: c instanceof PublicKeyCredential,
                  responseInstance: c.response instanceof AuthenticatorAssertionResponse,
                  id: c.id, json: c.toJSON(), clientDataJSON: b64u(c.response.clientDataJSON),
                  authenticatorData: b64u(c.response.authenticatorData),
                  signature: b64u(c.response.signature),
                  userHandle: c.response.userHandle ? b64u(c.response.userHandle) : null};
    }, function (e) { rp.login = {ok: false, name: e.name, message: e.message}; });
};
</script>""",
    "/passkey-frame": """<!doctype html><title>passkey frame</title>
<iframe id="f" src="http://127.0.0.1:{port}/passkey"
        allow="publickey-credentials-get *; publickey-credentials-create *"></iframe>""",
    # Like business.holyheld.com: just the account (email) now, a passkey next.
    "/identifier": """<!doctype html><title>identifier</title><form>
  <input type="email" id="ui-input-v-2" autocomplete="email" placeholder="a@work.com">
  <button type="submit">Sign In</button>
</form>""",
    # A field nothing marks as a login field: only an explicit fill uses it.
    "/bare": """<!doctype html><title>bare</title><div><input type="text" id="who"></div>""",
    "/plain": """<!doctype html><title>plain</title><p>No login form here.</p>""",
    "/frame": """<!doctype html><title>frame</title><p>top</p>
<iframe id="f" src="http://127.0.0.1:{port}/classic" width="500" height="200"></iframe>""",
}


def totp_codes(secret=TOTP_SECRET, period=30):
    """RFC 6238 codes for the current and previous period."""
    key = base64.b32decode(secret)
    codes = set()
    for step in (0, -1):
        counter = int(time.time()) // period + step
        digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
        offset = digest[-1] & 0x0F
        value = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
        codes.add(f"{value % 10**6:06d}")
    return codes


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# --- fixtures --------------------------------------------------------------


def build_database(path, port):
    kp = create_database(path, password=DB_PASSWORD)
    root = kp.root_group
    alice = kp.add_entry(root, "Single", "alice", "s3cret", url=f"http://127.0.0.1:{port}/")
    alice.otp = f"otpauth://totp/Single:alice?secret={TOTP_SECRET}&period=30&digits=6&issuer=Single"
    kp.add_entry(root, "Multi B", "bob", "pw-bob", url=f"http://127.0.0.2:{port}/")
    kp.add_entry(root, "Multi C", "carol", "pw-carol", url=f"http://127.0.0.2:{port}/")
    # Where KeePassXC files new passkeys; present, so it doesn't ask to create it.
    kp.add_group(root, "KeePassXC-Browser Passkeys")
    # Pre-approved browser association, as KeePassXC stores it after the user
    # names the connection in its dialog (CustomData "KPXC_BROWSER_<id>").
    id_key, _ = sodium.keypair()
    key_b64 = base64.b64encode(id_key).decode()
    meta = kp.tree.getroot().find("Meta")
    custom = meta.find("CustomData")
    if custom is None:
        custom = meta.makeelement("CustomData", {})
        meta.append(custom)
    item = custom.makeelement("Item", {})
    custom.append(item)
    for tag, text in (("Key", "KPXC_BROWSER_" + ASSOC_ID), ("Value", key_b64)):
        child = item.makeelement(tag, {})
        child.text = text
        item.append(child)
    kp.save()
    db_hash = hashlib.sha256(root.uuid.hex.encode()).hexdigest()
    return db_hash, key_b64


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


def serve(host, port):
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body = PAGES.get(self.path.split("?")[0], "<!doctype html><title>ok</title>ok")
            data = body.replace("{port}", str(port)).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        do_POST = do_GET

        def log_message(self, format: str, *args: Any) -> None:
            pass

    server = http.server.ThreadingHTTPServer((host, port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


# --- CDP ---------------------------------------------------------------------


class CDP:
    def __init__(self, ws_url):
        self.ws = websocket.create_connection(ws_url, timeout=30, suppress_origin=True)
        self.next_id = 0
        self.contexts = {}

    def call(self, method, **params):
        self.next_id += 1
        mid = self.next_id
        self.ws.send(json.dumps({"id": mid, "method": method, "params": params}))
        while True:
            msg = json.loads(self.ws.recv())
            if msg.get("id") == mid:
                if "error" in msg:
                    raise RuntimeError(f"{method}: {msg['error']}")
                return msg.get("result", {})
            self._event(msg)

    def _event(self, msg):
        method = msg.get("method")
        if method == "Runtime.executionContextCreated":
            ctx = msg["params"]["context"]
            self.contexts[ctx["id"]] = ctx
        elif method == "Runtime.executionContextDestroyed":
            self.contexts.pop(msg["params"]["executionContextId"], None)
        elif method == "Runtime.executionContextsCleared":
            self.contexts.clear()

    def evaluate(self, expression, context_id=None, await_promise=False):
        params = {"expression": expression, "returnByValue": True, "awaitPromise": await_promise}
        if context_id is not None:
            params["contextId"] = context_id
        result = self.call("Runtime.evaluate", **params)
        if "exceptionDetails" in result:
            raise RuntimeError(
                result["exceptionDetails"].get("text", "JS exception")
                + ": "
                + json.dumps(result["exceptionDetails"].get("exception", {}).get("description"))
            )
        return result["result"].get("value")

    def frame_tree(self):
        return self.call("Page.getFrameTree")["frameTree"]

    def context_for(self, frame_id, isolated):
        for ctx in list(self.contexts.values()):
            aux = ctx.get("auxData", {})
            if aux.get("frameId") != frame_id:
                continue
            if isolated and aux.get("type") == "isolated":
                try:
                    if self.evaluate(
                        "!!(window.external && window.external.extra && window.external.extra.kpxcprobe)", ctx["id"]
                    ):
                        return ctx["id"]
                except RuntimeError:
                    continue
            if not isolated and aux.get("isDefault"):
                return ctx["id"]
        return None


def wait_until(predicate, timeout=8.0, interval=0.2, what="condition"):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            last = predicate()
            if last:
                return last
        except (RuntimeError, OSError) as e:
            last = e
        time.sleep(interval)
    raise AssertionError(f"timed out waiting for {what} (last: {last!r})")


# --- the run -------------------------------------------------------------------


def sandbox_env(workdir):
    home = os.path.join(workdir, "home")
    env = {k: v for k, v in os.environ.items() if k in _PASS_ENV or k.startswith("LC_")}
    env.update(
        HOME=home,
        XDG_CONFIG_HOME=os.path.join(home, ".config"),
        XDG_DATA_HOME=os.path.join(home, ".local", "share"),
        XDG_CACHE_HOME=os.path.join(home, ".cache"),
        XDG_STATE_HOME=os.path.join(home, ".local", "state"),
        XDG_RUNTIME_DIR=_SANDBOX_RUNTIME,
        TMPDIR=os.path.join(workdir, "tmp"),
        KPXC_E2E_WORKDIR=workdir,
        KPXC_E2E_STAGE="sandbox",
        # Chromium's own sandbox can't nest inside bubblewrap; the pages are local.
        QTWEBENGINE_DISABLE_SANDBOX="1",
    )
    for key in ("XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME", "XDG_STATE_HOME", "TMPDIR"):
        os.makedirs(env[key], exist_ok=True)
    return env


def bwrap_command(workdir, env, argv):
    cmd = [
        "bwrap",
        "--ro-bind",
        "/",
        "/",
        "--dev",
        "/dev",
        "--proc",
        "/proc",
        "--tmpfs",
        "/dev/shm",
        "--tmpfs",
        "/tmp",
        "--tmpfs",
        "/run",
        "--tmpfs",
        "/var/tmp",
        "--perms",
        "0700",
        "--dir",
        _SANDBOX_RUNTIME,
        "--bind",
        workdir,
        workdir,
        "--unshare-all",
        "--die-with-parent",
        "--new-session",
        "--clearenv",
    ]
    for key, value in env.items():
        cmd += ["--setenv", key, value]
    return [*cmd, "--", *argv]


def start_xvfb():
    read_fd, write_fd = os.pipe()
    proc = subprocess.Popen(
        ["Xvfb", "-displayfd", str(write_fd), "-screen", "0", "1280x1024x24", "-nolisten", "tcp"],
        pass_fds=(write_fd,),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    os.close(write_fd)
    with os.fdopen(read_fd) as f:
        number = f.readline().strip()
    if not number:
        proc.kill()
        raise RuntimeError("Xvfb didn't start")
    return proc, ":" + number


def check_sandboxed(workdir):
    """Refuse to run the apps outside the sandbox the outer stages built."""
    problems = [k for k in _SESSION_ENV if k in os.environ]
    if not os.environ.get("HOME", "").startswith(workdir):
        problems.append("HOME")
    if os.path.exists("/run/dbus/system_bus_socket"):
        problems.append("system bus reachable")
    if os.environ.get("XDG_RUNTIME_DIR") != _SANDBOX_RUNTIME or "DBUS_SESSION_BUS_ADDRESS" not in os.environ:
        problems.append("runtime dir / session bus")
    if problems:
        raise SystemExit(f"not sandboxed ({', '.join(problems)}); run tests/e2e/run.py directly")


class Harness:
    def __init__(self, workdir):
        self.work = workdir
        self.port = free_port()
        self.cdp_port = free_port()
        self.procs = []
        self.servers = []
        self.runtime = os.environ["XDG_RUNTIME_DIR"]
        self.x_display = os.environ["DISPLAY"]
        self.env = dict(
            os.environ,
            QT_QPA_PLATFORM="offscreen",
            QTWEBENGINE_REMOTE_DEBUGGING=f"127.0.0.1:{self.cdp_port}",
            PYTHONDONTWRITEBYTECODE="1",
            KEEPASSXC_FALKON_DEBUG="1",
        )
        self.db_path = os.path.join(workdir, "e2e.kdbx")

    def url(self, host, path):
        return f"http://{host}:{self.port}{path}"

    def setup(self):
        self.db_hash, key_b64 = build_database(self.db_path, self.port)
        cfg = self.env["XDG_CONFIG_HOME"]
        self.kpxc_config = os.path.join(cfg, "keepassxc", "keepassxc.ini")
        self.kpxc_local_config = os.path.join(self.env["XDG_CACHE_HOME"], "keepassxc", "keepassxc.ini")
        # Quick Unlock asks Polkit (system bus) instead of the password; off.
        write(
            self.kpxc_local_config, "\n".join(["[Security]", "QuickUnlock=false", "LockDatabaseScreenLock=false", ""])
        )
        write(
            self.kpxc_config,
            "\n".join(
                [
                    "[General]",
                    "ConfigVersion=2",
                    "SingleInstance=false",
                    "RememberLastDatabases=false",
                    "AutoSaveAfterEveryChange=true",
                    "UpdateCheckMessageShown=true",
                    "[GUI]",
                    "CheckForUpdates=false",
                    "ShowTrayIcon=false",
                    "[Browser]",
                    "Enabled=true",
                    "AlwaysAllowAccess=true",
                    "AlwaysAllowUpdate=true",
                    "UnlockDatabase=true",
                    "UpdateBinaryPath=false",
                    "Browser_AllowLocalhostWithPasskeys=true",
                    "[FdoSecrets]",
                    "Enabled=false",
                    "[SSHAgent]",
                    "Enabled=false",
                    "",
                ]
            ),
        )
        profile = os.path.join(cfg, "falkon", "profiles", "e2e")
        version = subprocess.run(["falkon", "--version"], env=self.env, capture_output=True, text=True).stdout.split()[
            -1
        ]
        write(os.path.join(profile, "version"), version + "\n")
        write(
            os.path.join(profile, "settings.ini"),
            "\n".join(
                [
                    "[Plugin-Settings]",
                    "AllowedPlugins=python:keepassxc_falkon, python:kpxc_e2e_probe",
                    "[PasswordManager]",
                    "Backend=keepassxc",
                    "[Web-Browser-Settings]",
                    "AutoCompletePasswords=true",
                    "SavePasswordsOnSites=true",
                    "[Web-URL-Settings]",
                    "homepage=about:blank",
                    "afterLaunch=0",
                    "",
                ]
            ),
        )
        write(
            os.path.join(profile, "extensions", "keepassxc.json"),
            json.dumps({"associations": {self.db_hash: {"id": ASSOC_ID, "key": key_b64}}, "options": {}}),
        )
        plugins = os.path.join(cfg, "falkon", "plugins")
        os.makedirs(plugins, exist_ok=True)
        os.symlink(os.path.join(REPO, "keepassxc_falkon"), os.path.join(plugins, "keepassxc_falkon"))
        os.symlink(os.path.join(REPO, "tests", "e2e", "kpxc_e2e_probe"), os.path.join(plugins, "kpxc_e2e_probe"))

        for host in ("127.0.0.1", "127.0.0.2"):
            self.servers.append(serve(host, self.port))

    def start(self):
        # KeePassXC goes on the sandbox's virtual display, so the test can
        # press keys in its passkey dialogs; Falkon stays offscreen.
        self.x = XDisplay(self.x_display)
        kpxc_env = dict(self.env, QT_QPA_PLATFORM="xcb")

        with open(os.path.join(self.work, "keepassxc.log"), "w") as log:
            kpxc = subprocess.Popen(
                [
                    "keepassxc",
                    "--config",
                    self.kpxc_config,
                    "--localconfig",
                    self.kpxc_local_config,
                    "--pw-stdin",
                    self.db_path,
                ],
                env=kpxc_env,
                stdin=subprocess.PIPE,
                stdout=log,
                stderr=subprocess.STDOUT,
                text=True,
            )
        assert kpxc.stdin is not None  # stdin=PIPE
        kpxc.stdin.write(DB_PASSWORD + "\n")
        kpxc.stdin.close()
        self.procs.append(kpxc)
        sock = os.path.join(self.runtime, "app", "org.keepassxc.KeePassXC", "org.keepassxc.KeePassXC.BrowserServer")
        wait_until(lambda: os.path.exists(sock), timeout=20, what="KeePassXC browser socket")
        time.sleep(2)  # the socket comes up before --pw-stdin has opened the database

        self.falkon_log = os.path.join(self.work, "falkon.log")
        with open(self.falkon_log, "w") as flog:
            falkon = subprocess.Popen(
                ["falkon", "-r", "-p", "e2e", "about:blank"], env=self.env, stdout=flog, stderr=subprocess.STDOUT
            )
        self.procs.append(falkon)

        def page_target():
            with urllib.request.urlopen(f"http://127.0.0.1:{self.cdp_port}/json", timeout=2) as r:
                targets = [t for t in json.load(r) if t.get("type") == "page"]
            return targets[0] if targets else None

        target = wait_until(page_target, timeout=30, what="Falkon's DevTools endpoint")
        self.cdp = CDP(target["webSocketDebuggerUrl"])
        self.cdp.call("Page.enable")
        self.cdp.call("Runtime.enable")

    def unlock(self):
        """Unlock the way a user does: type the password into the dialog
        KeePassXC showed when the plugin asked it to unlock."""
        self.x.type_text("Unlock Database - KeePassXC", DB_PASSWORD)

    def dbus(self, method, *args):
        cmd = [
            "dbus-send",
            "--session",
            "--print-reply",
            "--dest=org.keepassxc.KeePassXC.MainWindow",
            "/keepassxc",
            f"org.keepassxc.KeePassXC.MainWindow.{method}",
            *args,
        ]
        return subprocess.run(cmd, env=self.env, capture_output=True, text=True, check=True).stdout

    def stop(self):
        if getattr(self, "x", None) is not None:
            self.x.close()
        for proc in reversed(self.procs):
            proc.terminate()
            try:
                proc.wait(10)
            except subprocess.TimeoutExpired:
                proc.kill()
        for server in self.servers:
            server.shutdown()

    # --- helpers for checks ---

    def navigate(self, url):
        self.cdp.call("Page.navigate", url=url)
        wait_until(
            lambda: self.cdp.evaluate(f"location.href === {json.dumps(url)} && document.readyState === 'complete'"),
            what=f"load of {url}",
        )
        return self.cdp.frame_tree()

    def main_eval(self, expr):
        return self.cdp.evaluate(expr)

    def probe(self, method, *args, obj="kpxcprobe"):
        frame_id = self.cdp.frame_tree()["frame"]["id"]
        ctx = wait_until(lambda: self.cdp.context_for(frame_id, isolated=True), what="probe context")
        call_args = ", ".join(json.dumps(a) for a in args)
        sep = ", " if args else ""
        expr = f"new Promise(function (res) {{ window.external.extra.{obj}.{method}({call_args}{sep}res); }})"
        return self.cdp.evaluate(expr, ctx, await_promise=True)


def fields(h, user_sel, pass_sel, root="document"):
    return h.main_eval(
        f"(function(){{var r={root};var u=r.querySelector({json.dumps(user_sel)}),"
        f"p=r.querySelector({json.dumps(pass_sel)});"
        "return [u ? u.value : null, p ? p.value : null];})()"
    )


def run_checks(h):
    results = []

    def check(name):
        def deco(fn):
            try:
                fn()
            except Exception as e:  # noqa: BLE001 -- report every check, keep going
                results.append((name, False, f"{type(e).__name__}: {e}"))
                print(f"FAIL  {name}: {e}", flush=True)
            else:
                results.append((name, True, ""))
                print(f"ok    {name}", flush=True)
            return fn

        return deco

    single = lambda path: h.url("127.0.0.1", path)  # noqa: E731

    # First, before anything on 127.0.0.1 is looked up (and cached for the site).
    @check("a page without login fields doesn't query KeePassXC")
    def _():
        url = single("/plain")
        h.navigate(url)
        time.sleep(1.5)
        assert json.loads(h.probe("usernames", url)) == []  # alice would show if it had asked

    @check("KeePassXC is Falkon's active password backend")
    def _():
        h.navigate(single("/classic"))
        assert h.probe("activeBackend") == "KeePassXC"

    @check("classic form is filled on load")
    def _():
        h.navigate(single("/classic"))
        wait_until(
            lambda: fields(h, "input[name=user]", "input[name=pass]") == ["alice", "s3cret"], what="filled classic form"
        )

    @check("late, nameless, formless fields are filled and page listeners see it")
    def _():
        h.navigate(single("/spa"))
        wait_until(
            lambda: fields(h, "#app input:not([type=password])", "#app input[type=password]") == ["alice", "s3cret"],
            what="filled SPA fields",
        )
        assert h.main_eval("window.__events") >= 2

    @check("fields inside an open shadow root are filled")
    def _():
        h.navigate(single("/shadow"))
        wait_until(
            lambda: (
                fields(
                    h, "input[type=email]", "input[type=password]", root="document.querySelector('x-login').shadowRoot"
                )
                == ["alice", "s3cret"]
            ),
            what="filled shadow-DOM fields",
        )

    @check("identifier-first page (email field only) is filled on load")
    def _():
        h.navigate(single("/identifier"))
        wait_until(
            lambda: h.main_eval("document.getElementById('ui-input-v-2').value") == "alice",
            what="email filled",
        )

    @check("explicit fill uses the focused field when no login form is recognised")
    def _():
        h.navigate(single("/bare"))
        time.sleep(1.5)
        assert h.main_eval("document.getElementById('who').value") == "", "not filled on load"
        h.main_eval("document.getElementById('who').focus()")
        h.probe("pressFillShortcut", obj="kpxcui")
        wait_until(lambda: h.main_eval("document.getElementById('who').value") == "alice", what="focused field filled")

    @check("sign-up form (new-password fields) is left alone")
    def _():
        h.navigate(single("/signup"))
        time.sleep(3)
        assert fields(h, "input[name=email]", "input[name=pw]") == ["", ""]

    @check("several matching entries: nothing filled, Falkon lists both usernames")
    def _():
        h.navigate(h.url("127.0.0.2", "/classic"))
        time.sleep(3)
        assert fields(h, "input[name=user]", "input[name=pass]") == ["", ""]
        assert sorted(json.loads(h.probe("usernames", h.url("127.0.0.2", "/classic")))) == ["bob", "carol"]

    @check("right-click menu lists the site's entries and fills the picked one")
    def _():
        h.navigate(h.url("127.0.0.2", "/classic"))
        labels = json.loads(h.probe("menuLabels", obj="kpxcui"))
        assert labels[:2] == ["bob \u2014 Multi B", "carol \u2014 Multi C"] or labels[:2] == [
            "carol \u2014 Multi C",
            "bob \u2014 Multi B",
        ], labels
        assert labels[-1] == "KeePassXC settings\u2026", labels
        pick = 0 if labels[0].startswith("carol") else 1
        h.probe("triggerMenu", pick, obj="kpxcui")
        wait_until(
            lambda: fields(h, "input[name=user]", "input[name=pass]") == ["carol", "pw-carol"],
            what="fill from the menu",
        )

    @check("fill shortcut: the only matching entry is filled at once")
    def _():
        h.navigate(single("/classic"))
        wait_until(lambda: fields(h, "input[name=user]", "input[name=pass]") == ["alice", "s3cret"], what="auto-fill")
        h.main_eval(
            "var u = document.querySelector('input[name=user]'); u.value = '';"
            "document.querySelector('input[name=pass]').value = ''; u.focus();"
        )
        h.probe("pressFillShortcut", obj="kpxcui")
        wait_until(
            lambda: fields(h, "input[name=user]", "input[name=pass]") == ["alice", "s3cret"],
            what="fill from the shortcut",
        )
        assert json.loads(h.probe("popup", obj="kpxcui")) is None, "no menu needed for a single entry"

    @check("fill shortcut: several entries pop up under the field, Enter takes the first")
    def _():
        h.navigate(h.url("127.0.0.2", "/classic"))
        h.main_eval("document.querySelector('input[name=user]').focus()")
        h.probe("pressFillShortcut", obj="kpxcui")
        popup = wait_until(lambda: json.loads(h.probe("popup", obj="kpxcui")), what="the account popup")
        entries = sorted(popup["labels"][:2])
        assert entries == ["bob \u2014 Multi B", "carol \u2014 Multi C"], popup
        assert popup["active"] == popup["labels"][0], popup
        x, y = popup["at"]
        field_bottom = h.main_eval("document.querySelector('input[name=user]').getBoundingClientRect().bottom")
        assert 0 <= x < popup["view"][0], popup
        assert abs(y - field_bottom) <= 4, (popup, field_bottom)  # right under the field, not mid-page
        user = popup["active"].split(" ")[0]
        h.probe("triggerPopupActive", obj="kpxcui")
        wait_until(
            lambda: fields(h, "input[name=user]", "input[name=pass]") == [user, f"pw-{user}"],
            what="fill from the popup",
        )

    @check("toolbar button is on the navigation bar")
    def _():
        assert json.loads(h.probe("button", obj="kpxcui"))["shown"] is True

    @check("toolbar button: badge counts the tab's entries (page and login iframe)")
    def _():
        h.navigate(h.url("127.0.0.2", "/frame"))
        wait_until(lambda: json.loads(h.probe("button", obj="kpxcui"))["badge"] in ("1", "3"), what="a badge")
        h.probe("toolbarMenu", obj="kpxcui")  # looks up every site in the tab
        badge = json.loads(h.probe("button", obj="kpxcui"))["badge"]
        assert badge == "3", badge  # bob and carol for the page, alice for the iframe

    @check("toolbar menu groups the page's and the login iframe's entries")
    def _():
        items = json.loads(h.probe("toolbarMenu", obj="kpxcui"))
        texts = [i["text"] for i in items]
        assert texts[0] == "127.0.0.2", texts
        assert "127.0.0.1" in texts, texts
        split = texts.index("127.0.0.1")
        assert sorted(texts[1:split]) == ["bob \u2014 Multi B", "carol \u2014 Multi C"], texts
        assert texts[split + 1] == "alice \u2014 Single", texts
        alice = items[split + 1]
        assert alice["sub"] == ["Fill", "Copy username", "Copy password", "Copy TOTP"], alice
        bob = next(i for i in items if i["text"].startswith("bob"))
        assert bob["sub"] == ["Fill", "Copy username", "Copy password"], bob
        assert texts[-1] == "KeePassXC settings\u2026", texts

    @check("copy username: plain text")
    def _():
        h.probe("triggerToolbar", "alice \u2014 Single", "Copy username", obj="kpxcui")
        assert json.loads(h.probe("clipboard", obj="kpxcui")) == {"text": "alice", "secret": False}

    @check("copy password: marked secret, cleared after the timeout")
    def _():
        h.probe("setOption", "clipboard_clear_seconds", 2, obj="kpxcui")
        h.probe("triggerToolbar", "alice \u2014 Single", "Copy password", obj="kpxcui")
        assert json.loads(h.probe("clipboard", obj="kpxcui")) == {"text": "s3cret", "secret": True}
        wait_until(
            lambda: json.loads(h.probe("clipboard", obj="kpxcui"))["text"] == "", timeout=5, what="clipboard cleared"
        )

    @check("copy TOTP: the entry's current code")
    def _():
        h.probe("triggerToolbar", "alice \u2014 Single", "Copy TOTP", obj="kpxcui")
        clip = wait_until(
            lambda: (lambda c: c if c["text"] else None)(json.loads(h.probe("clipboard", obj="kpxcui"))),
            what="TOTP on the clipboard",
        )
        assert clip["secret"], (clip, totp_codes())
        assert clip["text"] in totp_codes(), (clip, totp_codes())

    @check("toolbar menu Fill fills the iframe")
    def _():
        h.navigate(h.url("127.0.0.2", "/frame"))

        def iframe_values():
            children = h.cdp.frame_tree().get("childFrames") or []
            ctx = children and h.cdp.context_for(children[0]["frame"]["id"], isolated=False)
            return ctx and h.cdp.evaluate(
                "[document.querySelector('input[name=user]').value,document.querySelector('input[name=pass]').value]",
                ctx,
            )

        wait_until(lambda: iframe_values() == ["alice", "s3cret"], what="auto-filled iframe")
        h.cdp.evaluate("void 0")
        children = h.cdp.frame_tree()["childFrames"]
        ctx = h.cdp.context_for(children[0]["frame"]["id"], isolated=False)
        h.cdp.evaluate(
            "document.querySelector('input[name=user]').value = 'someone';"
            "document.querySelector('input[name=pass]').value = 'else'",
            ctx,
        )
        h.probe("toolbarMenu", obj="kpxcui")
        h.probe("triggerToolbar", "alice \u2014 Single", "Fill", obj="kpxcui")
        wait_until(lambda: iframe_values() == ["alice", "s3cret"], what="iframe refilled from the menu")

    @check("settings dialog shows a healthy connection")
    def _():
        h.navigate(single("/classic"))
        h.probe("settingsTexts", obj="kpxcui")
        expected = {
            "KeePassXC is running",
            "Database is unlocked",
            f"Connected as \u201c{ASSOC_ID}\u201d",
            "Falkon stores passwords in KeePassXC",
        }
        wait_until(
            lambda: expected <= set(json.loads(h.probe("settingsTextsNow", obj="kpxcui"))), what="settings status"
        )

    @check("cross-origin iframe is filled with its own origin's entry")
    def _():
        tree = h.navigate(h.url("127.0.0.2", "/frame"))

        def iframe_values():
            children = h.cdp.frame_tree().get("childFrames") or []
            if not children:
                return None
            ctx = h.cdp.context_for(children[0]["frame"]["id"], isolated=False)
            if ctx is None:
                return None
            return h.cdp.evaluate(
                "[document.querySelector('input[name=user]').value,document.querySelector('input[name=pass]').value]",
                ctx,
            )

        assert tree is not None
        wait_until(lambda: iframe_values() == ["alice", "s3cret"], what="filled iframe")

    @check("Falkon's save flow stores a new login in KeePassXC")
    def _():
        url = h.url("localhost", "/classic")
        h.navigate(url)
        assert json.loads(h.probe("entries", url)) == []
        h.probe("addEntry", url, "dave", "pw-dave")
        wait_until(
            lambda: (
                [(e["username"], e["password"]) for e in json.loads(h.probe("entries", url))] == [("dave", "pw-dave")]
            ),
            what="saved entry",
        )

    @check("Falkon's update flow changes the password of that entry")
    def _():
        url = h.url("localhost", "/classic")
        assert h.probe("updatePassword", url, "dave", "pw-dave-2") is True
        wait_until(
            lambda: (
                [(e["username"], e["password"]) for e in json.loads(h.probe("entries", url))] == [("dave", "pw-dave-2")]
            ),
            what="updated entry",
        )

    @check("saves reached the database file")
    def _():
        # KeePassXC files browser-saved entries in this group, titled by host,
        # and autosaves shortly after the change.
        def on_disk():
            out = subprocess.run(
                ["keepassxc-cli", "show", "-q", "-s", h.db_path, "KeePassXC-Browser Passwords/localhost"],
                input=DB_PASSWORD + "\n",
                capture_output=True,
                text=True,
                env=h.env,
            )
            return "dave" in out.stdout and "pw-dave-2" in out.stdout

        wait_until(on_disk, timeout=15, interval=1, what="entry in the .kdbx file")

    @check("locked database: no fill; unlocking fills the open page")
    def _():
        h.dbus("lockAllDatabases")
        time.sleep(1)
        h.navigate(single("/classic"))
        time.sleep(2)
        assert fields(h, "input[name=user]", "input[name=pass]") == ["", ""]
        h.unlock()
        wait_until(
            lambda: fields(h, "input[name=user]", "input[name=pass]") == ["alice", "s3cret"],
            timeout=10,
            what="fill after unlock",
        )

    @check("a save made while locked is written once unlocked")
    def _():
        url = h.url("localhost", "/classic")
        h.navigate(url)
        h.dbus("lockAllDatabases")
        time.sleep(1)
        h.probe("addEntry", url, "erin", "pw-erin")
        time.sleep(1.5)
        h.unlock()
        wait_until(
            lambda: (
                ("erin", "pw-erin") in [(e["username"], e["password"]) for e in json.loads(h.probe("entries", url))]
            ),
            timeout=10,
            what="deferred save",
        )

    passkey_url = h.url("localhost", "/passkey")
    origin = f"http://localhost:{h.port}"
    rp_id_hash = hashlib.sha256(b"localhost").digest()
    stash: dict[str, Any] = {}

    def b64u(text):
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))

    def rp_result(name, timeout=20):
        return wait_until(lambda: h.main_eval(f"rp.{name}"), timeout=timeout, what=f"rp.{name}")

    @check("passkeys: the page sees a platform authenticator, no conditional UI")
    def _():
        h.navigate(passkey_url)
        got = h.cdp.evaluate(
            "Promise.all([PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable(),"
            "PublicKeyCredential.isConditionalMediationAvailable()])",
            await_promise=True,
        )
        assert got == [True, False], got
        aborted = h.cdp.evaluate(
            "(function(){var c=new AbortController();var p=navigator.credentials.get({mediation:'conditional',"
            "signal:c.signal,publicKey:{challenge:new Uint8Array(32)}}).then(function(){return 'resolved'},"
            "function(e){return e.name});c.abort();return p;})()",
            await_promise=True,
        )
        assert aborted == "AbortError", aborted

    @check("passkeys: register in KeePassXC (verified like a relying party)")
    def _():
        h.navigate(passkey_url)
        h.main_eval("startRegister()")
        h.x.press(PASSKEY_DIALOG, *CONFIRM)
        reg = rp_result("reg")
        assert reg["ok"], reg
        assert reg["instance"], reg
        assert reg["responseInstance"], reg
        assert reg["rawIdMatches"], reg
        assert reg["alg"] == -7, reg
        assert reg["transports"] == ["internal"], reg
        client_data = json.loads(b64u(reg["json"]["response"]["clientDataJSON"]))
        assert client_data["type"] == "webauthn.create", client_data
        assert client_data["challenge"] == h.main_eval("rp.regChallenge"), client_data
        assert client_data["origin"] == origin, client_data
        auth_data = b64u(reg["authenticatorData"])
        assert auth_data[:32] == rp_id_hash, ("rpIdHash", auth_data.hex())
        assert auth_data[32] & 0x01, ("user present flag", auth_data[32])
        assert auth_data[32] & 0x40, ("attested credential data flag", auth_data[32])
        cred_len = int.from_bytes(auth_data[53:55], "big")
        assert auth_data[55 : 55 + cred_len] == b64u(reg["id"]), "credential id in authenticator data"
        assert attested_auth_data(b64u(reg["json"]["response"]["attestationObject"])) == auth_data
        assert b64u(reg["json"]["response"]["authenticatorData"]) == auth_data, "toJSON vs getter"
        key = load_der_public_key(b64u(reg["publicKey"]))
        assert isinstance(key, ec.EllipticCurvePublicKey), key
        assert key.curve.name == "secp256r1", key
        stash.update(id=reg["id"], key=key, user=h.main_eval("rp.userId"))

    @check("passkeys: the passkey is in the database file")
    def _():
        def stored():
            out = subprocess.run(
                [
                    "keepassxc-cli",
                    "show",
                    "-q",
                    "-a",
                    "KPEX_PASSKEY_CREDENTIAL_ID",
                    h.db_path,
                    "KeePassXC-Browser Passkeys/E2E RP (Passkey)",
                ],
                input=DB_PASSWORD + "\n",
                capture_output=True,
                text=True,
                env=h.env,
            )
            return out.stdout.strip() == stash["id"]

        try:
            wait_until(stored, timeout=15, interval=1, what="passkey entry on disk")
        except AssertionError as e:
            raise AssertionError(f"{e}; KeePassXC windows: {h.x.titles()}") from None

    @check("passkeys: sign in with it (signature verifies)")
    def _():
        h.navigate(passkey_url)
        h.main_eval(f"startLogin({json.dumps(stash['id'])})")
        h.x.press(PASSKEY_DIALOG, *CONFIRM)
        login = rp_result("login")
        assert login["ok"], login
        assert login["instance"], login
        assert login["responseInstance"], login
        assert login["id"] == stash["id"], login
        assert login["userHandle"] == stash["user"], login
        client_json = b64u(login["clientDataJSON"])
        client_data = json.loads(client_json)
        assert client_data["type"] == "webauthn.get", client_data
        assert client_data["challenge"] == h.main_eval("rp.loginChallenge"), client_data
        assert client_data["origin"] == origin, client_data
        auth_data = b64u(login["authenticatorData"])
        assert auth_data[:32] == rp_id_hash, ("rpIdHash", auth_data.hex())
        assert auth_data[32] & 0x01, ("user present flag", auth_data[32])
        stash["key"].verify(
            b64u(login["signature"]), auth_data + hashlib.sha256(client_json).digest(), ec.ECDSA(hashes.SHA256())
        )

    @check("passkeys: discoverable sign-in (no allowCredentials)")
    def _():
        h.navigate(passkey_url)
        h.main_eval("startLogin()")
        h.x.press(PASSKEY_DIALOG, *CONFIRM)
        login = rp_result("login")
        assert login["ok"], login
        assert login["id"] == stash["id"], login

    @check("passkeys: cancelling in KeePassXC gives NotAllowedError")
    def _():
        h.navigate(passkey_url)
        h.main_eval(f"startLogin({json.dumps(stash['id'])})")
        h.x.press(PASSKEY_DIALOG, "Escape")
        login = rp_result("login")
        assert not login["ok"], login
        assert login["name"] == "NotAllowedError", login

    @check("passkeys: registering an excluded credential gives InvalidStateError")
    def _():
        h.navigate(passkey_url)
        h.main_eval(f"startRegister({json.dumps(stash['id'])})")
        reg = rp_result("reg")
        assert not reg["ok"], reg
        assert reg["name"] == "InvalidStateError", reg

    @check("passkeys: a frame from another site is refused")
    def _():
        h.navigate(h.url("localhost", "/passkey-frame"))

        def frame_ctx():
            children = h.cdp.frame_tree().get("childFrames") or []
            return children and h.cdp.context_for(children[0]["frame"]["id"], isolated=False)

        ctx = wait_until(frame_ctx, what="iframe context")
        wait_until(lambda: h.cdp.evaluate("typeof startLogin === 'function'", ctx), what="iframe script")
        h.cdp.evaluate("startLogin()", ctx)
        login = wait_until(lambda: h.cdp.evaluate("rp.login", ctx), what="iframe result")
        assert not login["ok"], login
        assert login["name"] == "NotAllowedError", login

    @check("passkeys: a locked database is unlocked, then the request goes through")
    def _():
        h.navigate(passkey_url)
        h.dbus("lockAllDatabases")
        time.sleep(1)
        h.main_eval(f"startLogin({json.dumps(stash['id'])})")
        time.sleep(2)
        h.unlock()
        h.x.press(PASSKEY_DIALOG, *CONFIRM)
        login = rp_result("login")
        assert login["ok"], login
        assert login["id"] == stash["id"], login

    @check("passkeys: registered right after a password save, both reach the file")
    def _():
        # KeePassXC loses a change that arrives while it is saving the
        # previous one; the plugin spaces its writes so this can't happen.
        h.navigate(passkey_url)
        h.probe("addEntry", h.url("localhost", "/classic"), "frank", "pw-frank")
        h.main_eval('startRegister(null, "E2E RP 2")')
        h.x.press(PASSKEY_DIALOG, *CONFIRM, timeout=20)
        reg = rp_result("reg", timeout=30)
        assert reg["ok"], reg

        def both_on_disk():
            kp = PyKeePass(h.db_path, password=DB_PASSWORD)
            frank = kp.find_entries(username="frank", first=True)
            passkey = kp.find_entries(title="E2E RP 2 (Passkey)", first=True)
            return (
                frank is not None
                and frank.password == "pw-frank"
                and passkey is not None
                and passkey.get_custom_property("KPEX_PASSKEY_CREDENTIAL_ID") == reg["id"]
            )

        wait_until(both_on_disk, timeout=20, interval=1, what="password and passkey in the .kdbx file")

    return results


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--workdir")
    parser.add_argument("--keep", action="store_true", help="keep the work dir")
    args = parser.parse_args()
    stage = os.environ.get("KPXC_E2E_STAGE")
    me = [sys.executable, "-B", os.path.abspath(__file__)] + (["--keep"] if args.keep else [])

    if stage == "inner":
        return inner(os.environ["KPXC_E2E_WORKDIR"], args.keep)

    if stage == "sandbox":
        # Inside bubblewrap: a virtual display, then a private session bus.
        xvfb, display = start_xvfb()
        try:
            env = dict(os.environ, DISPLAY=display, KPXC_E2E_STAGE="inner")
            return subprocess.call(["dbus-run-session", "--", *me], env=env)
        finally:
            xvfb.terminate()
            xvfb.wait(10)

    workdir = os.path.abspath(args.workdir or tempfile.mkdtemp(prefix="kpxc-e2e-"))
    os.makedirs(workdir, exist_ok=True)
    return subprocess.call(bwrap_command(workdir, sandbox_env(workdir), me))


def inner(workdir, keep):
    check_sandboxed(workdir)
    h = Harness(workdir)
    try:
        h.setup()
        h.start()
        results = run_checks(h)
    finally:
        h.stop()
    with open(h.falkon_log, encoding="utf-8", errors="replace") as f:
        log = f.read()
    tracebacks = log.count("Traceback")
    if tracebacks:
        print(f"\nFalkon log has {tracebacks} Python traceback(s) — see {h.falkon_log}")
    failed = [r for r in results if not r[1]]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    if not keep and not failed and not tracebacks:
        shutil.rmtree(workdir, ignore_errors=True)
    else:
        print(f"work dir kept: {workdir}")
    return 1 if failed or tracebacks else 0


if __name__ == "__main__":
    sys.exit(main())
