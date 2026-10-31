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
  // Words (not substrings: generated ids like "id__q8user" don't count) in a
  // field's name, id, placeholder or label that say "account name here".
  var USER_WORDS = { user: 1, username: 1, userid: 1, login: 1, email: 1, mail: 1, account: 1,
                     acct: 1, identifier: 1, signin: 1, uid: 1 };
  var SEARCH_WORDS = { search: 1, query: 1, find: 1, filter: 1 };

  function attr(el, name) {
    return (el.getAttribute(name) || "").toLowerCase();
  }

  function words(el) {
    var text = [el.name, el.id, el.getAttribute("placeholder"), el.getAttribute("aria-label")].join(" ");
    return text.replace(/([a-z])([A-Z])/g, "$1 $2").toLowerCase().split(/[^a-z0-9]+/);
  }

  function hasWord(el, set) {
    return words(el).some(function (w) { return set[w] === 1; });
  }

  function isSearch(el) {
    return attr(el, "enterkeyhint") === "search" || /search/.test(attr(el, "autocomplete")) ||
      !!el.closest('[role="search"], search') || hasWord(el, SEARCH_WORDS);
  }

  function visible(el) {
    if (!el.isConnected || el.disabled || el.readOnly) return false;
    var r = el.getBoundingClientRect();
    if (r.width < 2 || r.height < 2) return false;
    // Parked off the page (a common way to hide a field) isn't shown.
    if (r.right + window.scrollX <= 0 || r.bottom + window.scrollY <= 0) return false;
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
    if (/one-time-code|cc-/.test(attr(el, "autocomplete")) || isSearch(el)) return false;
    return visible(el);
  }

  // Does a lone field look like where the account name goes?
  function looksLikeUsername(el) {
    if (/\b(username|email|webauthn)\b/.test(attr(el, "autocomplete"))) return true;
    if (attr(el, "type") === "email") return true;
    return hasWord(el, USER_WORDS);
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

    // Identifier-first sign-in (the account name now; a password or a
    // passkey on the next step): a field marked as the username, or the only
    // username-like field of its form (or page) — never where a password
    // field shares the scope, which is a sign-up or change-password form.
    if (!groups.length) {
      var lone = users.filter(function (u) {
        var scope = scopeOf(u);
        if (scopes.some(function (s) { return s.scope === scope; })) return false;
        if (/\b(username|webauthn)\b/.test(attr(u, "autocomplete"))) return true;
        var alone = users.filter(function (v) { return scopeOf(v) === scope; }).length === 1;
        return alone && looksLikeUsername(u);
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

  function focusedInput() {
    var e = document.activeElement;
    while (e && e.shadowRoot && e.shadowRoot.activeElement) e = e.shadowRoot.activeElement;
    return e && e.localName === "input" ? e : null;
  }

  function fill(creds) {
    var any = false;
    var groups = findLogins();
    // Asked for explicitly but no login form recognised: the focused field.
    if (!groups.length && creds.overwrite) {
      var focused = focusedInput();
      if (focused && attr(focused, "type") === "password" && visible(focused)) {
        groups = [{ user: null, pass: focused }];
      } else if (focused && isUsername(focused)) {
        groups = [{ user: focused, pass: null }];
      }
    }
    groups.forEach(function (g) {
      if (g.user && creds.username) any = setValue(g.user, creds.username, creds.overwrite) || any;
      if (g.pass && creds.password) any = setValue(g.pass, creds.password, creds.overwrite) || any;
    });
    return any;
  }

  // Only the top frame can reach the plugin: QtWebEngine installs the web
  // channel there alone. Sub-frames post their messages up and the top
  // frame's isolated world relays them. A page script can see (or forge)
  // these messages, but they're only hints — the plugin finds the frame
  // by its real URL and answers only the document holding the token.
  var isTop = window.top === window;
  var queue = [];               // calls waiting for the bridge (top frame)

  function call(method, args) {
    if (bridge) bridge[method].apply(bridge, args);
    else if (queue.length < 20) queue.push([method, args]);
  }

  function relay(kind, msg, args) {
    if (isTop) {
      call(kind, args);
    } else {
      var up = {};
      up[kind === "loginFormFound" ? "__kpxcFalkon" : "__kpxcFalkonPasskey"] = msg;
      try { window.top.postMessage(up, "*"); } catch (e) { /* detached */ }
    }
  }

  function report(info) {
    var msg = { token: token, href: String(window.location.href), info: JSON.stringify(info) };
    relay("loginFormFound", msg, [msg.token, msg.href, msg.info]);
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

  // Passkeys: passkeys.js (the page's world) posts requests to this window;
  // add the token and pass them on. The plugin answers only a request this
  // document really has pending (hasPasskeyRequest), so one forged by
  // another frame goes nowhere.
  var passkeyRequests = {};
  window.addEventListener("message", function (e) {
    if (e.source !== window) return;
    var m = e.data && e.data.__kpxcPasskeyRequest;
    if (!m || typeof m.id !== "string" || typeof m.kind !== "string" || typeof m.options !== "string") return;
    passkeyRequests[m.id] = true;
    var msg = { token: token, href: String(window.location.href), id: m.id, kind: m.kind, options: m.options };
    relay("passkeyRequest", msg, [msg.token, msg.href, msg.id, msg.kind, msg.options]);
  });

  window.__kpxcFalkon = {
    token: token,
    fill: fill,
    // After an unlock: report again so the plugin fills what it now can.
    rescan: function () { reported = new WeakSet(); scan(); },
    hasPasskeyRequest: function (id) { return passkeyRequests[id] === true; },
    passkeyResult: function (id, result) {
      if (passkeyRequests[id] !== true) return false;
      delete passkeyRequests[id];
      window.postMessage({ __kpxcPasskeyResponse: { id: id, result: result } }, "*");
      return true;
    },
  };

  // Injected at document creation (so it listens before any site script
  // runs); the fields appear as the document is parsed.
  scan();
  document.addEventListener("DOMContentLoaded", scan);
  new MutationObserver(scheduleScan).observe(document, {
    childList: true, subtree: true,
    attributes: true, attributeFilter: ["type", "class", "style", "hidden"],
  });
  document.addEventListener("focusin", function (e) {
    if (e.target && e.target.localName === "input") scheduleScan();
  }, true);

  if (!isTop) return;

  window.addEventListener("message", function (e) {
    if (e.source === window || !e.data) return;
    var r = e.data.__kpxcFalkon;
    if (r && typeof r.token === "string" && typeof r.href === "string" && typeof r.info === "string") {
      call("loginFormFound", [r.token, r.href, r.info]);
    }
    var p = e.data.__kpxcFalkonPasskey;
    if (p && typeof p.token === "string" && typeof p.href === "string" && typeof p.id === "string" &&
        typeof p.kind === "string" && typeof p.options === "string") {
      call("passkeyRequest", [p.token, p.href, p.id, p.kind, p.options]);
    }
  });

  function tryHook() {
    var ext = window.external;
    var b = ext && ext.extra && ext.extra.keepassxc;
    if (bridge || !b || typeof b.loginFormFound !== "function") return !!bridge;
    bridge = b;
    queue.splice(0).forEach(function (c) { call(c[0], c[1]); });
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
