// KeePassXC for Falkon — passkeys (WebAuthn) served by KeePassXC.
//
// Falkon exposes the WebAuthn API but nothing answers it (a passkey request
// just hangs). This script runs in the PAGE's world at document creation and
// stands in for navigator.credentials.create/get when they ask for a
// passkey (publicKey). It holds no secrets and no privileges: it serializes
// the request (binary fields as base64url, as KeePassXC expects) and posts
// it to this frame's isolated-world script (fill.js), which hands it to the
// plugin. The plugin works out the requesting origin itself, KeePassXC asks
// the user and signs, and the answer comes back the same way, rebuilt here
// as a PublicKeyCredential.
(function () {
  "use strict";
  if (!window.isSecureContext || typeof PublicKeyCredential === "undefined" ||
      typeof CredentialsContainer === "undefined") return;

  var REQUEST = "__kpxcPasskeyRequest";
  var RESPONSE = "__kpxcPasskeyResponse";
  var nativeCreate = CredentialsContainer.prototype.create;
  var nativeGet = CredentialsContainer.prototype.get;
  var pending = new Map();

  // KeePassXC signs clientData with "crossOrigin": false, which is only true
  // for the top frame and frames from the same origin.
  function allowedHere() {
    try {
      return window.top === window || window.top.location.origin === window.location.origin;
    } catch (e) {
      return false;
    }
  }

  function bytes(source) {
    if (source instanceof ArrayBuffer) return new Uint8Array(source);
    if (ArrayBuffer.isView(source)) return new Uint8Array(source.buffer, source.byteOffset, source.byteLength);
    throw new TypeError("Expected an ArrayBuffer or a view on one");
  }

  function toB64url(source) {
    var b = bytes(source);
    var s = "";
    for (var i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function fromB64url(text) {
    var t = String(text).replace(/-/g, "+").replace(/_/g, "/");
    while (t.length % 4) t += "=";
    var s = atob(t);
    var out = new Uint8Array(s.length);
    for (var i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
    return out.buffer;
  }

  // Binary values anywhere (extension inputs) → base64url.
  function plain(value) {
    if (value instanceof ArrayBuffer || ArrayBuffer.isView(value)) return toB64url(value);
    if (Array.isArray(value)) return value.map(plain);
    if (value && typeof value === "object") {
      var out = {};
      Object.keys(value).forEach(function (k) { out[k] = plain(value[k]); });
      return out;
    }
    return value;
  }

  function descriptors(list) {
    return Array.prototype.map.call(list || [], function (d) {
      return { type: d.type, id: toB64url(d.id), transports: d.transports };
    });
  }

  function creationOptions(pk) {
    var params = pk.pubKeyCredParams && pk.pubKeyCredParams.length ? pk.pubKeyCredParams
      : [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }];   // the spec's defaults
    return {
      rp: plain(pk.rp),
      user: { id: toB64url(pk.user.id), name: pk.user.name, displayName: pk.user.displayName },
      challenge: toB64url(pk.challenge),
      pubKeyCredParams: params,
      timeout: pk.timeout,
      excludeCredentials: descriptors(pk.excludeCredentials),
      authenticatorSelection: pk.authenticatorSelection,
      attestation: pk.attestation,
      extensions: plain(pk.extensions || {}),
    };
  }

  function assertionOptions(pk) {
    return {
      challenge: toB64url(pk.challenge),
      timeout: pk.timeout,
      rpId: pk.rpId,
      allowCredentials: descriptors(pk.allowCredentials),
      userVerification: pk.userVerification,
      extensions: plain(pk.extensions || {}),
    };
  }

  function make(proto, props) {
    var object = Object.create(proto);
    Object.keys(props).forEach(function (k) {
      Object.defineProperty(object, k, { value: props[k], enumerable: typeof props[k] !== "function" });
    });
    return object;
  }

  // Objects that pass `instanceof PublicKeyCredential` and carry what sites
  // and WebAuthn libraries read (including toJSON and the getters).
  function credential(c, kind) {
    var r = c.response || {};
    var attachment = c.authenticatorAttachment || "platform";
    var extensions = r.clientExtensionResults || {};
    var json = {
      id: c.id, rawId: c.id, type: "public-key", authenticatorAttachment: attachment,
      clientExtensionResults: extensions, response: { clientDataJSON: r.clientDataJSON },
    };
    var response;
    if (kind === "create") {
      var transports = ["internal"];
      json.response.attestationObject = r.attestationObject;
      json.response.authenticatorData = r.authenticatorData;
      json.response.publicKey = r.publicKey;
      json.response.publicKeyAlgorithm = r.publicKeyAlgorithm;
      json.response.transports = transports;
      response = make(AuthenticatorAttestationResponse.prototype, {
        clientDataJSON: fromB64url(r.clientDataJSON),
        attestationObject: fromB64url(r.attestationObject),
        getTransports: function () { return transports.slice(); },
        getAuthenticatorData: function () { return fromB64url(r.authenticatorData); },
        getPublicKey: function () { return r.publicKey ? fromB64url(r.publicKey) : null; },
        getPublicKeyAlgorithm: function () { return r.publicKeyAlgorithm; },
      });
    } else {
      json.response.authenticatorData = r.authenticatorData;
      json.response.signature = r.signature;
      if (r.userHandle) json.response.userHandle = r.userHandle;
      response = make(AuthenticatorAssertionResponse.prototype, {
        clientDataJSON: fromB64url(r.clientDataJSON),
        authenticatorData: fromB64url(r.authenticatorData),
        signature: fromB64url(r.signature),
        userHandle: r.userHandle ? fromB64url(r.userHandle) : null,
      });
    }
    return make(PublicKeyCredential.prototype, {
      id: c.id,
      rawId: fromB64url(c.id),
      type: "public-key",
      authenticatorAttachment: attachment,
      response: response,
      getClientExtensionResults: function () { return JSON.parse(JSON.stringify(extensions)); },
      toJSON: function () { return JSON.parse(JSON.stringify(json)); },
    });
  }

  function aborted(signal) {
    return signal.reason !== undefined ? signal.reason : new DOMException("The operation was aborted.", "AbortError");
  }

  function request(kind, options) {
    var pk = options.publicKey;
    var signal = options.signal;
    if (signal && signal.aborted) return Promise.reject(aborted(signal));
    if (!allowedHere()) {
      return Promise.reject(new DOMException(
        "KeePassXC passkeys work in the page itself, not in frames embedded from another site.",
        "NotAllowedError"));
    }
    var payload;
    try {
      payload = JSON.stringify(kind === "create" ? creationOptions(pk) : assertionOptions(pk));
    } catch (e) {
      return Promise.reject(e instanceof TypeError ? e : new TypeError(String(e)));
    }
    var id = window.crypto.randomUUID ? crypto.randomUUID() : Date.now() + "-" + Math.random().toString(36).slice(2);
    return new Promise(function (resolve, reject) {
      // KeePassXC's dialog times out on its own; this only guards against
      // an answer that never comes (KeePassXC gone, plugin disabled).
      var wait = (pk.timeout > 0 ? Math.min(pk.timeout, 600000) : 300000) + 30000;
      var timer = setTimeout(function () {
        finish(new DOMException("The operation either timed out or was not allowed.", "NotAllowedError"));
      }, wait);
      function onAbort() { finish(aborted(signal)); }
      function finish(error, value) {
        if (!pending.has(id)) return;
        pending.delete(id);
        clearTimeout(timer);
        if (signal) signal.removeEventListener("abort", onAbort);
        if (error) reject(error); else resolve(value);
      }
      if (signal) signal.addEventListener("abort", onAbort);
      pending.set(id, { kind: kind, finish: finish });
      var message = {};
      message[REQUEST] = { id: id, kind: kind, options: payload };
      window.postMessage(message, "*");
    });
  }

  window.addEventListener("message", function (e) {
    if (e.source !== window) return;
    var m = e.data && e.data[RESPONSE];
    if (!m || typeof m.id !== "string" || !pending.has(m.id)) return;
    var p = pending.get(m.id);
    var answer;
    try {
      answer = JSON.parse(m.result);
    } catch (x) {
      answer = { error: { name: "UnknownError", message: "Unreadable answer from KeePassXC" } };
    }
    if (answer.error) {
      p.finish(answer.error.name === "TypeError" ? new TypeError(answer.error.message)
        : new DOMException(answer.error.message, answer.error.name));
      return;
    }
    try {
      p.finish(null, credential(answer.credential, p.kind));
    } catch (x) {
      p.finish(new DOMException("Malformed passkey from KeePassXC", "UnknownError"));
    }
  });

  // Conditional mediation (passkeys offered in a login field's autofill) isn't
  // supported: report it unavailable, and leave such a request pending
  // until the site aborts it, as an unanswered native one would be.
  function conditional(options) {
    var signal = options.signal;
    return new Promise(function (_resolve, reject) {
      if (!signal) return;
      if (signal.aborted) reject(aborted(signal));
      else signal.addEventListener("abort", function () { reject(aborted(signal)); });
    });
  }

  CredentialsContainer.prototype.create = function create(options) {
    if (options && options.publicKey) return request("create", options);
    return nativeCreate.apply(this, arguments);
  };
  CredentialsContainer.prototype.get = function get(options) {
    if (options && options.publicKey) {
      return options.mediation === "conditional" ? conditional(options) : request("get", options);
    }
    return nativeGet.apply(this, arguments);
  };

  PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable = function () {
    return Promise.resolve(allowedHere());
  };
  PublicKeyCredential.isConditionalMediationAvailable = function () {
    return Promise.resolve(false);
  };
  if (typeof PublicKeyCredential.getClientCapabilities === "function") {
    PublicKeyCredential.getClientCapabilities = function () {
      var here = allowedHere();
      return Promise.resolve({
        conditionalCreate: false, conditionalGet: false, hybridTransport: false,
        passkeyPlatformAuthenticator: here, userVerifyingPlatformAuthenticator: here,
        relatedOrigins: false, signalAllAcceptedCredentials: false,
        signalCurrentUserDetails: false, signalUnknownCredential: false,
      });
    };
  }
})();
