"""A stand-in for KeePassXC's browser server, for tests.

Speaks the real wire protocol (flat JSON, crypto_box, nonce increments,
error replies without nonces, unsolicited database-locked/unlocked
broadcasts) on a Unix socket, from a background thread — so a client in
the test's thread can block in waitForReadyRead while this answers.
Mirrors src/browser/BrowserAction.cpp closely enough to catch protocol
mistakes, including KeePassXC's habit of splitting input on '}'.

It runs in a child process (``FakeProcess``): PySide's blocking
``waitForReadyRead`` keeps the GIL, so a server thread in the test's own
process couldn't answer while the client waits. The proxy forwards
attribute reads/writes and method calls over a pipe.
"""

import base64
import json
import multiprocessing
import os
import socket
import threading
import time
import uuid as uuidlib
from urllib.parse import urlsplit

from keepassxc_falkon import sodium


def b64(data):
    return base64.b64encode(data).decode("ascii")


def unb64(text):
    return base64.b64decode(text)


class FakeKeePassXC:
    def __init__(self, path):
        self.path = path
        self.locked = False
        self.db_hash = "f" * 64
        self.keys = {}                 # association id -> idKey
        self.entries = []              # dicts: uuid, login, password, name, url
        self.associate_as = "falkon-test"   # None: the user cancels the dialog
        self.logins_delay = 0.0        # seconds — an access-confirm dialog
        self.unlock_requests = 0
        self.received = []             # (action, inner message or None)
        self.received_at = []          # time.time() of each, same order
        self.unencrypted_nested = False
        self.coalesce_next = None      # a message to glue in front of the next reply
        self.passkey_response = {"errorCode": 15}   # what passkeys-get/-register answer
        self._clients = {}             # clientID -> state
        self._conns = []
        self._lock = threading.Lock()
        self._server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._server.bind(path)
        self._server.listen()
        self._stop = False
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()

    # --- test controls ------------------------------------------------

    def add_entry(self, url, login, password, name=None, totp=None):
        entry = {"uuid": uuidlib.uuid4().hex, "login": login, "password": password,
                 "name": name or urlsplit(url).hostname, "url": url, "totp": totp}
        self.entries.append(entry)
        return entry

    def set_locked(self, locked):
        self.locked = locked
        self.broadcast({"action": "database-locked" if locked else "database-unlocked"})

    def broadcast(self, message):
        data = json.dumps(message).encode()
        with self._lock:
            for conn in list(self._conns):
                try:
                    conn.sendall(data)
                except OSError:
                    pass

    def actions(self):
        return [a for a, _ in self.received]

    def clear_received(self):
        self.received.clear()
        self.received_at.clear()

    def set_entry_password(self, index, password):
        self.entries[index]["password"] = password

    def close(self):
        self._stop = True
        try:
            self._server.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self._server.close()
        with self._lock:
            for conn in self._conns:
                try:
                    conn.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                conn.close()
        if os.path.exists(self.path):
            os.unlink(self.path)

    # --- server -------------------------------------------------------

    def _accept_loop(self):
        while not self._stop:
            try:
                conn, _ = self._server.accept()
            except OSError:
                return
            with self._lock:
                self._conns.append(conn)
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn):
        while not self._stop:
            try:
                data = conn.recv(1 << 20)
            except OSError:
                break
            if not data:
                break
            # KeePassXC (BrowserHost::parseSocketData) splits on '}' — a
            # nested object in the plaintext envelope would break there.
            pieces = data.split(b"}")
            if len(pieces) > 2 or pieces[-1].strip():
                self.unencrypted_nested = True
            message = json.loads(data)
            count = len(self.received)
            reply = self._process(message)
            self.received_at += [time.time()] * (len(self.received) - count)
            if reply:
                data = json.dumps(reply).encode()
                if self.coalesce_next is not None:
                    data = json.dumps(self.coalesce_next).encode() + data
                    self.coalesce_next = None
                with self._lock:
                    conn.sendall(data)
        with self._lock:
            if conn in self._conns:
                self._conns.remove(conn)
        conn.close()

    def _error(self, action, code):
        return {"action": action, "errorCode": str(code), "error": f"error {code}"}

    def _process(self, message):
        action = message.get("action")
        client_id = message.get("clientID")
        if not client_id:
            return None
        state = self._clients.setdefault(client_id, {"box": None, "client_pk": None, "associated": False})

        if action == "change-public-keys":
            self.received.append((action, None))
            nonce = unb64(message["nonce"])
            pk, sk = sodium.keypair()
            state["client_pk"] = message["publicKey"]
            state["box"] = sodium.Box(sk, unb64(message["publicKey"]))
            state["associated"] = False
            return {"action": action, "publicKey": b64(pk), "nonce": b64(sodium.increment_nonce(nonce)),
                    "success": "true", "version": "2.8.0"}

        if self.locked:
            if state["client_pk"] is None:
                return self._error(action, 3)
            if message.get("triggerUnlock") == "true":
                self.unlock_requests += 1
            self.received.append((action, None))
            return self._error(action, 1)

        nonce = unb64(message["nonce"])
        inner = json.loads(state["box"].decrypt(unb64(message["message"]), nonce))
        self.received.append((action, inner))
        reply_nonce = sodium.increment_nonce(nonce)

        def respond(**params):
            body = {"version": "2.8.0", "success": "true", "nonce": b64(reply_nonce), **params}
            ct = state["box"].encrypt(json.dumps(body).encode(), reply_nonce)
            return {"action": action, "message": b64(ct), "nonce": b64(reply_nonce)}

        if action == "get-databasehash":
            return respond(hash=self.db_hash)

        if action == "associate":
            if inner.get("key") != state["client_pk"]:
                return self._error(action, 8)
            if self.associate_as is None:
                return self._error(action, 6)
            self.keys[self.associate_as] = inner.get("idKey") or inner["key"]
            state["associated"] = True
            return respond(hash=self.db_hash, id=self.associate_as)

        if action == "test-associate":
            if self.keys.get(inner.get("id")) != inner.get("key"):
                return self._error(action, 8)
            state["associated"] = True
            return respond(hash=self.db_hash, id=inner["id"])

        if action == "get-logins":
            if not state["associated"]:
                return self._error(action, 8)
            if self.logins_delay:
                time.sleep(self.logins_delay)
            host = urlsplit(inner["url"]).hostname
            found = [{k: e[k] for k in ("uuid", "login", "password", "name")} | {"group": "Browser"}
                     | ({"totp": e["totp"]} if e.get("totp") else {})
                     for e in self.entries if urlsplit(e["url"]).hostname == host]
            if not found:
                return self._error(action, 15)
            return respond(count=len(found), entries=found, hash=self.db_hash, id=inner.get("id", ""))

        if action == "get-totp":
            if not state["associated"]:
                return self._error(action, 8)
            entry = next((e for e in self.entries if e["uuid"] == inner.get("uuid")), None)
            if entry is None:
                return self._error(action, 18)
            return respond(totp=entry.get("totp") or "")

        if action in ("passkeys-get", "passkeys-register"):
            if not state["associated"]:
                return self._error(action, 8)
            return respond(response=self.passkey_response)

        if action == "set-login":
            if not state["associated"]:
                return self._error(action, 8)
            if inner.get("uuid"):
                for e in self.entries:
                    if e["uuid"] == inner["uuid"]:
                        e["login"], e["password"] = inner["login"], inner["password"]
                        break
                else:
                    self.add_entry(inner["url"], inner["login"], inner["password"])
            else:
                self.add_entry(inner["url"], inner["login"], inner["password"])
            return respond(count=None, entries=None, error="success", hash=self.db_hash)

        return self._error(action, 12)


def _child(path, conn):
    server = FakeKeePassXC(path)
    conn.send(("ready", None))
    while True:
        try:
            op, name, args = conn.recv()
        except EOFError:
            break
        try:
            if op == "close":
                server.close()
                conn.send(("ok", None))
                break
            if op == "get":
                value = getattr(server, name)
                conn.send(("callable", None) if callable(value) else ("ok", value))
            elif op == "set":
                setattr(server, name, args)
                conn.send(("ok", None))
            else:
                positional, keywords = args
                conn.send(("ok", getattr(server, name)(*positional, **keywords)))
        except Exception as e:  # report to the test instead of hanging it
            conn.send(("error", repr(e)))


class FakeProcess:
    """Test-side handle on a FakeKeePassXC running in a child process."""

    def __init__(self, path):
        ctx = multiprocessing.get_context("spawn")
        self.__dict__["_conn"], child = ctx.Pipe()
        self.__dict__["path"] = path
        proc = ctx.Process(target=_child, args=(path, child), daemon=True)
        proc.start()
        self.__dict__["_proc"] = proc
        assert self._rpc(None, None, None, already_sent=True) is None   # "ready"

    def _rpc(self, op, name, args, already_sent=False):
        if not already_sent:
            self._conn.send((op, name, args))
        status, value = self._conn.recv()
        if status == "error":
            raise RuntimeError(value)
        if status == "callable":
            return lambda *a, **kw: self._rpc("call", name, (a, kw))
        return value

    def __getattr__(self, name):
        return self._rpc("get", name, None)

    def __setattr__(self, name, value):
        self._rpc("set", name, value)

    def close(self):
        if self._proc.is_alive():
            self._rpc("close", None, None)
        self._proc.join(5)
