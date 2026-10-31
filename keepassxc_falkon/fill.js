// KeePassXC for Falkon — login-field detection and filling.
//
// Runs in Falkon's SafeJsWorld (an isolated world: page scripts can't see
// this code or its globals, though they share the DOM) in every frame.
//
// It never asks for credentials. It only tells the plugin "this frame has
// login fields" (with a per-document token page scripts can't read); the
// plugin finds the frame itself, looks credentials up for the URL Chromium
// reports for that frame, and pushes them back into this world by running
// window.__kpxcFalkon.fill(...) in that exact frame.
(function () {
  "use strict";
  if (window.__kpxcFalkon) return;

  var token = (window.crypto && crypto.randomUUID) ? crypto.randomUUID()
    : "kpxc-" + Date.now() + "-" + Math.random().toString(36).slice(2);
  var bridge = null;            // top frame only: window.external.extra.keepassxc
  var reported = new WeakSet();   // fields we already told the plugin about
  var filled = new WeakMap();     // field -> the value we put there
  var setNativeValue = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set;

  var USER_TYPES = { "": 1, text: 1, email: 1, tel: 1 };
  var USER_HINT = /user|login|email|e-mail|account|identifier|acct/i;

  function attr(el, name) {
    return (el.getAttribute(name) || "").toLowerCase();
  }

  function visible(el) {
    if (!el.isConnected || el.disabled || el.readOnly) return false;
    var r = el.getBoundingClientRect();
    if (r.width < 2 || r.height < 2) return false;
    var s = window.getComputedStyle(el);
    return s.visibility !== "hidden" && s.display !== "none" && parseFloat(s.opacity || "1") > 0.05;
  }

  // Every <input>, including those inside open shadow roots.
  function allInputs() {
    var out = Array.prototype.slice.call(document.querySelectorAll("input"));
    var walker = document.createTreeWalker(document.documentElement || document, NodeFilter.SHOW_ELEMENT);
    var stack = [];
    for (var n = walker.currentNode; n; n = walker.nextNode()) {
      if (n.shadowRoot) stack.push(n.shadowRoot);
    }
    while (stack.length) {
      var root = stack.pop();
      var found = root.querySelectorAll("*");
      for (var i = 0; i < found.length; i++) {
        if (found[i].localName === "input") out.push(found[i]);
        if (found[i].shadowRoot) stack.push(found[i].shadowRoot);
      }
    }
    return out;
  }

  function isPassword(el) {
    return attr(el, "type") === "password" && visible(el);
  }

  function isUsername(el) {
    var type = attr(el, "type");
    if (!(type in USER_TYPES)) return false;
    if (/one-time-code|cc-|search/.test(attr(el, "autocomplete"))) return false;
    return visible(el);
  }

  function scopeOf(el) {
    return el.form || el.getRootNode();
  }

  function precedes(a, b) {
    return !!(a.compareDocumentPosition(b) & Node.DOCUMENT_POSITION_FOLLOWING);
  }

  // [{user: <input>|null, pass: <input>|null}] — one group per login form.
  function findLogins() {
    var inputs = allInputs();
    var passwords = inputs.filter(isPassword);
    var users = inputs.filter(isUsername);
    var groups = [];

    // Group password fields by form (or by root when there is no <form>).
    var scopes = [];
    passwords.forEach(function (p) {
      var scope = scopeOf(p);
      var entry = scopes.find(function (s) { return s.scope === scope; });
      if (!entry) scopes.push(entry = { scope: scope, fields: [] });
      entry.fields.push(p);
    });

    scopes.forEach(function (s) {
      // Registration / change-password forms mark the new password fields.
      var current = s.fields.filter(function (p) {
        return attr(p, "autocomplete").indexOf("new-password") < 0;
      });
      if (!current.length && s.fields.length === 1) current = s.fields;
      current.forEach(function (p) {
        var candidates = users.filter(function (u) { return scopeOf(u) === s.scope && precedes(u, p); });
        var hinted = candidates.filter(function (u) { return /username|email/.test(attr(u, "autocomplete")); });
        var user = (hinted.length ? hinted : candidates).pop() || null;
        groups.push({ user: user, pass: p });
      });
    });

    // Identifier-first sign-in (username now, password on the next step):
    // only where no password field shares the scope (not a sign-up form).
    if (!groups.length) {
      var lone = users.filter(function (u) {
        if (scopes.some(function (s) { return s.scope === scopeOf(u); })) return false;
        if (/username/.test(attr(u, "autocomplete"))) return true;
        return u.form && USER_HINT.test((u.name || "") + " " + (u.id || "")) &&
          users.filter(function (v) { return v.form === u.form; }).length === 1;
      });
      if (lone.length) groups.push({ user: lone[0], pass: null });
    }
    return groups;
  }

  function setValue(el, value, overwrite) {
    if (el.value === value) return false;
    // Don't clobber what the user typed (unless they asked for this fill).
    if (!overwrite && el.value && filled.get(el) !== el.value) return false;
    // The isolated world's own setter is the native one, so frameworks
    // that patch .value in the page world (React) see a real change.
    setNativeValue.call(el, value);
    filled.set(el, value);
    el.dispatchEvent(new Event("input", { bubbles: true, composed: true }));
    el.dispatchEvent(new Event("change", { bubbles: true, composed: true }));
    return true;
  }

  function fill(creds) {
    var any = false;
    findLogins().forEach(function (g) {
      if (g.user && creds.username) any = setValue(g.user, creds.username, creds.overwrite) || any;
      if (g.pass && creds.password) any = setValue(g.pass, creds.password, creds.overwrite) || any;
    });
    return any;
  }

  // Only the top frame can reach the plugin: QtWebEngine installs the web
  // channel there alone. Sub-frames post their report up and the top
  // frame's isolated world relays it. A page script can see (or forge)
  // these messages, but they're only hints — the plugin finds the frame
  // by its real URL and fills only the document holding the token.
  var isTop = window.top === window;
  var pending = [];

  function send(msg) {
    if (bridge) bridge.loginFormFound(msg.token, msg.href, msg.info);
    else if (pending.length < 20) pending.push(msg);
  }

  function report(info) {
    var msg = { token: token, href: String(window.location.href), info: JSON.stringify(info) };
    if (isTop) {
      send(msg);
    } else {
      try { window.top.postMessage({ __kpxcFalkon: msg }, "*"); } catch (e) { /* detached */ }
    }
  }

  function scan() {
    var groups = findLogins();
    var fresh = groups.some(function (g) {
      return (g.pass && !reported.has(g.pass)) || (g.user && !reported.has(g.user));
    });
    if (!fresh) return;
    groups.forEach(function (g) {
      if (g.pass) reported.add(g.pass);
      if (g.user) reported.add(g.user);
    });
    report({ password: groups.some(function (g) { return !!g.pass; }) });
  }

  // DOM churn on busy pages: scan at most every 750 ms.
  var scanTimer = null;
  function scheduleScan() {
    if (scanTimer === null) {
      scanTimer = setTimeout(function () { scanTimer = null; scan(); }, 750);
    }
  }

  window.__kpxcFalkon = {
    token: token,
    fill: fill,
    // After an unlock: report again so the plugin fills what it now can.
    rescan: function () { reported = new WeakSet(); scan(); },
  };

  scan();
  new MutationObserver(scheduleScan).observe(document, {
    childList: true, subtree: true,
    attributes: true, attributeFilter: ["type", "class", "style", "hidden"],
  });
  document.addEventListener("focusin", function (e) {
    if (e.target && e.target.localName === "input") scheduleScan();
  }, true);

  if (!isTop) return;

  window.addEventListener("message", function (e) {
    var m = e.data && e.data.__kpxcFalkon;
    if (m && e.source !== window && typeof m.token === "string" &&
        typeof m.href === "string" && typeof m.info === "string") {
      send({ token: m.token, href: m.href, info: m.info });
    }
  });

  function tryHook() {
    var ext = window.external;
    var b = ext && ext.extra && ext.extra.keepassxc;
    if (bridge || !b || typeof b.loginFormFound !== "function") return !!bridge;
    bridge = b;
    pending.splice(0).forEach(send);
    return true;
  }

  // Falkon sets window.external up asynchronously over its web channel.
  if (!tryHook()) {
    var onCreated = function () {
      if (tryHook()) document.removeEventListener("_falkon_external_created", onCreated);
    };
    document.addEventListener("_falkon_external_created", onCreated);
    var tries = 0;
    var poll = setInterval(function () {
      if (tryHook() || ++tries > 50) clearInterval(poll);
    }, 100);
  }
})();
