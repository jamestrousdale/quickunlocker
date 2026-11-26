"use strict";

const $ = (id) => document.getElementById(id);
const b64uToBuf = (s) => {
  const b = atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4));
  return Uint8Array.from(b, (c) => c.charCodeAt(0)).buffer;
};
const bufToB64u = (buf) =>
  btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

async function api(path, body) {
  const r = await fetch(path, body === undefined ? {} : {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.detail || data.error || `HTTP ${r.status}`);
  return data;
}

// ---------------------------------------------------------------- unlock

async function getAssertion(options) {
  const credential = await navigator.credentials.get({
    publicKey: {
      ...options,
      challenge: b64uToBuf(options.challenge),
      allowCredentials: options.allowCredentials.map((c) => ({ type: c.type, id: b64uToBuf(c.id) })),
    },
  });
  return {
    id: credential.id,
    rawId: bufToB64u(credential.rawId),
    type: credential.type,
    response: {
      authenticatorData: bufToB64u(credential.response.authenticatorData),
      clientDataJSON: bufToB64u(credential.response.clientDataJSON),
      signature: bufToB64u(credential.response.signature),
      userHandle: credential.response.userHandle ? bufToB64u(credential.response.userHandle) : null,
    },
    clientExtensionResults: {},
  };
}

async function approve(req, btn) {
  btn.textContent = "Waiting for Face ID…";
  try {
    const assertion = await getAssertion(req.options);
    await api(`/api/unlock-requests/${encodeURIComponent(req.id)}/assertion`, assertion);
    $("feedback").textContent = `Unlock sent to ${req.pc_name}.`;
  } catch (e) {
    $("feedback").textContent = e.name === "NotAllowedError" ? "Cancelled." : `Error: ${e.message}`;
  }
}

let refreshing = false;
let busy = false;

async function runAction(btn, action) {
  if (busy) return;
  busy = true;
  btn.disabled = true;
  $("feedback").textContent = "";
  try {
    await action();
  } finally {
    busy = false;
    btn.disabled = false;
    await refresh();
  }
}

async function wake(name, btn) {
  btn.textContent = "Waking…";
  try {
    await api(`/api/pcs/${encodeURIComponent(name)}/wake`, {});
    $("feedback").textContent = `Wake sent to ${name}. Waiting for its lock screen.`;
  } catch (e) {
    $("feedback").textContent = e.message;
  }
}

async function refresh() {
  if (busy || refreshing) return;
  refreshing = true;
  try {
    const [pcs, reqs] = await Promise.all([api("/api/pcs"), api("/api/unlock-requests/pending")]);
    if (busy) return;
    const rows = new Map(pcs.map((pc) => [pc.pc_name, null]));
    for (const req of reqs) rows.set(req.pc_name, req);
    const ul = $("requests");
    ul.replaceChildren();
    $("status").textContent = reqs.length
      ? "Only approve an unlock you started."
      : rows.size ? "" : "No PCs found. Start enrollment from a PC.";

    for (const [name, req] of rows) {
      const li = document.createElement("li");
      const label = document.createElement("span");
      label.textContent = req ? `${name} · ${req.age}s ago` : name;
      const btn = document.createElement("button");
      btn.textContent = req ? "Unlock" : "Wake";
      btn.addEventListener("click", () =>
        runAction(btn, () => req ? approve(req, btn) : wake(name, btn)));
      li.append(label, btn);
      ul.append(li);
    }
  } catch (e) {
    $("status").textContent = `Can't reach relay: ${e.message}`;
  } finally {
    refreshing = false;
  }
}

// ---------------------------------------------------------------- enroll

const fingerprintStorageKey = "quickunlocker-passkey-fingerprints";

function knownFingerprints() {
  try {
    return new Map(JSON.parse(localStorage.getItem(fingerprintStorageKey) || "[]"));
  } catch {
    return new Map();
  }
}

async function enroll(session, options, fingerprints) {
  const cred = await navigator.credentials.create({
    publicKey: {
      ...options,
      challenge: b64uToBuf(options.challenge),
      user: { ...options.user, id: b64uToBuf(options.user.id) },
      excludeCredentials: (options.excludeCredentials || []).map((c) => ({ ...c, id: b64uToBuf(c.id) })),
    },
  });
  const publicKey = cred.response.getPublicKey?.();
  if (!publicKey) throw new Error("This browser could not read the passkey public key.");
  const digest = await crypto.subtle.digest("SHA-256", publicKey);
  const hex = Array.from(new Uint8Array(digest).slice(0, 10),
    (byte) => byte.toString(16).padStart(2, "0")).join("").toUpperCase();
  const fingerprint = hex.match(/.{4}/g).join("-");
  await api("/api/enroll/verify", {
    session,
    credential: {
      id: cred.id,
      rawId: bufToB64u(cred.rawId),
      type: cred.type,
      response: {
        clientDataJSON: bufToB64u(cred.response.clientDataJSON),
        attestationObject: bufToB64u(cred.response.attestationObject),
        transports: cred.response.getTransports ? cred.response.getTransports() : [],
      },
      clientExtensionResults: {},
    },
  });
  fingerprints.set(cred.id, fingerprint);
  try {
    localStorage.setItem(fingerprintStorageKey, JSON.stringify([...fingerprints].slice(-32)));
  } catch {
    // Enrollment still works if the browser disables storage.
  }
  return fingerprint;
}

async function reusePasskey(session, options, fingerprints) {
  const challenge = new Uint8Array(b64uToBuf(options.challenge));
  if (challenge.length !== 33 || challenge[0] !== 1) {
    throw new Error("The relay returned an invalid enrollment challenge.");
  }
  const credential = await getAssertion({
    ...options,
    userVerification: "required",
    allowCredentials: [...fingerprints.keys()].map((id) => ({ type: "public-key", id })),
  });
  const fingerprint = fingerprints.get(credential.id);
  if (!fingerprint) throw new Error("This browser has no fingerprint for that passkey.");
  await api("/api/enroll/reuse", { session, credential });
  return fingerprint;
}

async function showFingerprint(complete) {
  const buttons = [$("enrollBtn"), $("reuseBtn")];
  for (const btn of buttons) btn.disabled = true;
  try {
    const fingerprint = await complete();
    $("enrollResult").textContent = `Fingerprint: ${fingerprint}. Compare it with the fingerprint on the PC.`;
  } catch (e) {
    $("enrollResult").textContent = `Enrollment failed: ${e.message}`;
    for (const btn of buttons) btn.disabled = false;
  }
}

// ---------------------------------------------------------------- boot

if ($("enrollBtn")) {
  const session = new URLSearchParams(location.search).get("s");
  api("/api/enroll/options", { session }).then(({ options, reuse }) => {
    const fingerprints = knownFingerprints();
    const createButton = $("enrollBtn");
    const reuseButton = $("reuseBtn");
    $("enrollResult").textContent = "";
    createButton.addEventListener("click", () => showFingerprint(() => enroll(session, options, fingerprints)));
    createButton.disabled = false;
    if (reuse && fingerprints.size) {
      reuseButton.hidden = false;
      reuseButton.disabled = false;
      reuseButton.addEventListener("click", () => showFingerprint(() => reusePasskey(session, reuse, fingerprints)));
    }
  }).catch((error) => {
    $("enrollResult").textContent = error.message;
  });
} else {
  $("refresh").addEventListener("click", refresh);
  document.addEventListener("visibilitychange", () => { if (!document.hidden) refresh(); });
  refresh();
  setInterval(() => { if (!document.hidden) refresh(); }, 3000);
}
