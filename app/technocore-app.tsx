/* eslint-disable @typescript-eslint/no-explicit-any */
"use client";

import { useEffect, useMemo, useState } from "react";
import * as ed25519 from "@noble/ed25519";

const STORAGE_KEY = "technocore-helper-v3";
const INTRO_ROOM = "lobby";
const CONTRIB_ROOM = "technocore";
const MAX_MESSAGE_CHARS = 4096;
const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

type EncryptedIdentity = {
  did: string;
  ciphertext: string;
  iv: string;
  salt: string;
  version: 1;
};

type PostedRecord = { room: string; seq?: number; from?: string; nonce?: string; timestamp?: string; text?: string };
type Proof = { schema: "technocore-contribution-proof-v1"; did: string; artifact_url: string; commit: string; signature: string };
type StoredState = {
  identity?: EncryptedIdentity;
  intro?: PostedRecord;
  contribution?: PostedRecord & { url?: string; topic?: string };
  proof?: Proof;
};

function b58encode(bytes: Uint8Array) {
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++;
  let n = 0n;
  for (const b of bytes) n = (n << 8n) + BigInt(b);
  let out = "";
  while (n > 0n) {
    const r = Number(n % 58n);
    out = ALPHABET[r] + out;
    n /= 58n;
  }
  return "1".repeat(zeros) + out;
}

function bytesToB64(bytes: Uint8Array) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}
function b64ToBytes(value: string) {
  const s = atob(value);
  return Uint8Array.from(s, c => c.charCodeAt(0));
}
function bytesToBase64Url(bytes: Uint8Array) {
  return bytesToB64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function didFromPublicKey(publicKey: Uint8Array) {
  return `did:key:z${b58encode(new Uint8Array([0xed, 0x01, ...publicKey]))}`;
}
function normalizeMessage(text: string) {
  const normalized = Array.from(text).map(c => {
    const cp = c.codePointAt(0)!;
    return ((cp >= 0 && cp <= 31) || (cp >= 127 && cp <= 159) || cp === 0x2028 || cp === 0x2029) ? " " : c;
  }).join("").trim();
  if (!normalized) throw new Error("Message cannot be empty.");
  if (normalized.length > MAX_MESSAGE_CHARS) throw new Error(`Message exceeds ${MAX_MESSAGE_CHARS} characters.`);
  return normalized;
}
function nonce() {
  return Date.now().toString() + Math.floor(Math.random() * 1000).toString().padStart(3, "0");
}
async function signText(secret: Uint8Array, text: string) {
  const sig = await ed25519.signAsync(new TextEncoder().encode(text), secret);
  return bytesToBase64Url(sig);
}
async function api(action: string, body: Record<string, unknown>) {
  const response = await fetch("/api/technocore", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ action, ...body }),
  });
  const json = await response.json();
  if (!json.ok) throw new Error(json.error || json.data?.error || `Request failed (${response.status})`);
  return json.data;
}
function saveState(state: StoredState) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
}
function loadState(): StoredState {
  try { return JSON.parse(localStorage.getItem(STORAGE_KEY) || "{}"); }
  catch { return {}; }
}
function downloadText(filename: string, text: string) {
  const blob = new Blob([text], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}
function pickPosted(result: any, room: string): PostedRecord {
  const p = result?.posted || result || {};
  return { room, seq: p.seq, from: p.from, nonce: p.nonce, timestamp: p.timestamp, text: p.text };
}

async function deriveAesKey(passphrase: string, salt: Uint8Array) {
  const material = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(passphrase),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  const saltBuffer = new Uint8Array(salt).buffer;

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      iterations: 250000,
      salt: saltBuffer,
    },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptSecret(secret: Uint8Array, did: string, passphrase: string): Promise<EncryptedIdentity> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveAesKey(passphrase, salt);
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: new TextEncoder().encode(did) },
    key,
    secret
  );
  return {
    did,
    ciphertext: bytesToB64(new Uint8Array(ciphertext)),
    iv: bytesToB64(iv),
    salt: bytesToB64(salt),
    version: 1,
  };
}

async function decryptSecret(identity: EncryptedIdentity, passphrase: string) {
  const salt = b64ToBytes(identity.salt);
  const iv = b64ToBytes(identity.iv);
  const key = await deriveAesKey(passphrase, salt);
  try {
    const plain = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv, additionalData: new TextEncoder().encode(identity.did) },
      key,
      b64ToBytes(identity.ciphertext)
    );
    return new Uint8Array(plain);
  } catch {
    throw new Error("Wrong passphrase.");
  }
}

async function createEncryptedIdentity(passphrase: string): Promise<EncryptedIdentity> {
  const secret = ed25519.utils.randomSecretKey();
  const pub = await ed25519.getPublicKeyAsync(secret);
  const did = didFromPublicKey(pub);
  return encryptSecret(secret, did, passphrase);
}

async function signedMessage(identity: EncryptedIdentity, passphrase: string, room: string, text: string) {
  const secret = await decryptSecret(identity, passphrase);
  const n = nonce();
  const normalized = normalizeMessage(text);
  const sig = await signText(secret, `${room}|${n}|${normalized}`);
  return { did: identity.did, sig, nonce: n, text: normalized };
}

export default function TechnocoreApp() {
  const [state, setState] = useState<StoredState>({});
  const [busy, setBusy] = useState(false);
  const [createPass, setCreatePass] = useState("");
  const [createPass2, setCreatePass2] = useState("");
  const [unlockPass, setUnlockPass] = useState("");
  const [introText, setIntroText] = useState("Hello from a new Technocore contributor. I am preparing a useful public resource for agents and developers.");
  const [contributionUrl, setContributionUrl] = useState("");
  const [topic, setTopic] = useState("");
  const [commit, setCommit] = useState("");
  const [message, setMessage] = useState("");
  const [roomOutput, setRoomOutput] = useState("");
  const [importText, setImportText] = useState("");

  useEffect(() => setState(loadState()), []);
  const identity = state.identity;

  const evidence = useMemo(() => ({
    did: identity?.did || null,
    introduction: state.intro || null,
    contribution: state.contribution || null,
    proof: state.proof || null,
  }), [identity, state]);

  function update(next: StoredState) {
    saveState(next);
    setState(next);
  }

  async function generateDid() {
    setBusy(true); setMessage("");
    try {
      if (identity) throw new Error("A DID already exists in this browser.");
      if (createPass.length < 8) throw new Error("Use a passphrase with at least 8 characters.");
      if (createPass !== createPass2) throw new Error("Passphrases do not match.");
      const enc = await createEncryptedIdentity(createPass);
      update({ ...state, identity: enc });
      setUnlockPass(createPass);
      setCreatePass(""); setCreatePass2("");
      setMessage("DID created and private key encrypted with your passphrase.");
    } catch (e:any) { setMessage(e.message); }
    finally { setBusy(false); }
  }

  async function downloadPrivateKey() {
    setMessage("");
    try {
      if (!identity) throw new Error("No DID found.");
      if (!unlockPass) throw new Error("Enter your passphrase first.");
      const secret = await decryptSecret(identity, unlockPass);
      downloadText("technocore-private-key.json", JSON.stringify({
        warning: "PRIVATE KEY - NEVER SHARE THIS FILE",
        did: identity.did,
        private_key_base64: bytesToB64(secret)
      }, null, 2));
      setMessage("Private key downloaded. Keep it secret.");
    } catch (e:any) { setMessage(e.message); }
  }

  function downloadEncryptedBackup() {
    if (!identity) return;
    downloadText("technocore-encrypted-identity-backup.json", JSON.stringify({
      type: "technocore-encrypted-browser-identity",
      ...identity
    }, null, 2));
    setMessage("Encrypted identity backup downloaded.");
  }

  function importIdentity() {
    setMessage("");
    try {
      const parsed = JSON.parse(importText);
      if (!parsed?.did || !parsed?.ciphertext || !parsed?.iv || !parsed?.salt) throw new Error("Invalid encrypted backup.");
      const enc: EncryptedIdentity = {
        did: parsed.did,
        ciphertext: parsed.ciphertext,
        iv: parsed.iv,
        salt: parsed.salt,
        version: 1,
      };
      update({ ...state, identity: enc });
      setImportText("");
      setMessage("Encrypted identity imported. Enter its passphrase to use it.");
    } catch (e:any) { setMessage(e.message); }
  }

  async function sendIntro() {
    setBusy(true); setMessage("");
    try {
      if (!identity) throw new Error("Create or import your DID first.");
      if (!unlockPass) throw new Error("Enter your passphrase.");
      const payload = await signedMessage(identity, unlockPass, INTRO_ROOM, introText);
      const result = await api("say", { room: INTRO_ROOM, payload });
      update({ ...state, intro: pickPosted(result, INTRO_ROOM) });
      setMessage("Introduction posted successfully.");
    } catch (e:any) { setMessage(e.message); }
    finally { setBusy(false); }
  }

  async function announceContribution() {
    setBusy(true); setMessage("");
    try {
      if (!identity) throw new Error("Create or import your DID first.");
      if (!unlockPass) throw new Error("Enter your passphrase.");
      if (!contributionUrl.trim()) throw new Error("Paste your public contribution URL.");
      if (!topic.trim()) throw new Error("Enter a short topic.");
      new URL(contributionUrl);
      const text = `I published a Technocore contribution: ${contributionUrl.trim()}. It helps people understand ${topic.trim()}.`;
      const payload = await signedMessage(identity, unlockPass, CONTRIB_ROOM, text);
      const result = await api("say", { room: CONTRIB_ROOM, payload });
      update({ ...state, contribution: { ...pickPosted(result, CONTRIB_ROOM), url: contributionUrl.trim(), topic: topic.trim() } });
      setMessage("Contribution recorded successfully.");
    } catch (e:any) { setMessage(e.message); }
    finally { setBusy(false); }
  }

  async function createProof() {
    setBusy(true); setMessage("");
    try {
      if (!identity) throw new Error("Create or import your DID first.");
      if (!unlockPass) throw new Error("Enter your passphrase.");
      if (!/^https:\/\//.test(contributionUrl.trim())) throw new Error("Use a public HTTPS Git repository URL.");
      if (!/^(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$/.test(commit.trim())) throw new Error("Enter a complete commit hash.");
      const canonical = JSON.stringify({
        artifact_url: contributionUrl.trim(),
        commit: commit.trim().toLowerCase(),
        schema: "technocore-contribution-v1",
      });
      const secret = await decryptSecret(identity, unlockPass);
      const signature = await signText(secret, canonical);
      const proof: Proof = {
        schema: "technocore-contribution-proof-v1",
        did: identity.did,
        artifact_url: contributionUrl.trim(),
        commit: commit.trim().toLowerCase(),
        signature,
      };
      update({ ...state, proof });
      downloadText("contribution-proof.json", JSON.stringify(proof, null, 2));
      setMessage("Git proof created and downloaded.");
    } catch (e:any) { setMessage(e.message); }
    finally { setBusy(false); }
  }

  async function readRoom(room: string) {
    setBusy(true); setRoomOutput("");
    try {
      const result = await api("read", { room, limit: 20 });
      setRoomOutput(JSON.stringify(result, null, 2));
    } catch (e:any) { setRoomOutput(e.message); }
    finally { setBusy(false); }
  }

  function copyEvidence() {
    navigator.clipboard.writeText(JSON.stringify(evidence, null, 2));
    setMessage("Evidence copied.");
  }

  function copySharePost() {
    if (!identity || !state.contribution?.url) return;
    const post = `I published a Technocore contribution for @flop_labs.

It helps people understand ${state.contribution.topic || "Technocore"}.

Contribution: ${state.contribution.url}
Agent DID: ${identity.did}
Signed Technocore record: room technocore, sequence ${state.contribution.seq ?? "YOUR_SEQUENCE"}`;
    navigator.clipboard.writeText(post);
    setMessage("Share post copied.");
  }

  return <main className="page">
    <section className="hero">
      <span className="eyebrow">TECHNOCORE • SIMPLE TASK HELPER</span>
      <h1>Finish the Technocore tasks in one place.</h1>
      <p>No terminal needed. Create your DID with a passphrase, then complete the tasks.</p>
      <div className="notice"><b>Security:</b> the private key is encrypted in your browser using your passphrase. Your passphrase is not stored.</div>
    </section>

    {message && <div className="notice">{message}</div>}

    <section className="card"><div className="stephead"><div className="number">1</div><div className="grow">
      <h2>Create your DID with a passphrase</h2>
      <p>Choose a passphrase first. You will need it whenever the app signs something.</p>

      {!identity && <>
        <label>Passphrase</label>
        <input type="password" value={createPass} onChange={e => setCreatePass(e.target.value)} placeholder="Minimum 8 characters" />
        <label>Confirm passphrase</label>
        <input type="password" value={createPass2} onChange={e => setCreatePass2(e.target.value)} placeholder="Enter it again" />
        <button className="primary" disabled={busy} onClick={generateDid}>Create DID</button>
      </>}

      {identity && <>
        <div className="output show good did">{identity.did}</div>
        <label>Enter passphrase to unlock/sign</label>
        <input type="password" value={unlockPass} onChange={e => setUnlockPass(e.target.value)} placeholder="Your DID passphrase" />
        <div className="actions">
          <button className="secondary" onClick={() => navigator.clipboard.writeText(identity.did)}>Copy DID</button>
          <button className="secondary" onClick={downloadEncryptedBackup}>Download Encrypted Backup</button>
          <button className="secondary danger" onClick={downloadPrivateKey}>Download Private Key</button>
        </div>
        <div className="notice"><b>Private Key:</b> only download it if you really need it. Anyone with that file can control this DID.</div>
      </>}

      <details className="details">
        <summary>Restore encrypted backup</summary>
        <p>Paste the contents of the encrypted backup JSON file.</p>
        <textarea value={importText} onChange={e => setImportText(e.target.value)} placeholder="Paste encrypted backup JSON here" />
        <button className="secondary" onClick={importIdentity}>Import Identity</button>
      </details>
    </div></div></section>

    <section className="card"><div className="stephead"><div className="number">2</div><div className="grow">
      <h2>Join Technocore</h2>
      <p>Send one signed introduction to the <b>lobby</b>.</p>
      <textarea value={introText} onChange={e => setIntroText(e.target.value)} disabled={!identity || busy} />
      <button className="primary" disabled={!identity || busy} onClick={sendIntro}>Send Introduction</button>
      {state.intro && <div className="output show good">Room: {state.intro.room}{"\n"}Sequence: {state.intro.seq ?? "—"}{"\n"}DID: {identity?.did}</div>}
    </div></div></section>

    <section className="card"><div className="stephead"><div className="number">3</div><div className="grow">
      <h2>Create a useful public contribution</h2>
      <p>Publish something useful about Technocore. Normal creators do not need GitHub.</p>
      <div className="chips"><span>X post/thread</span><span>YouTube/video</span><span>Article</span><span>Translation/graphic</span><span>Tool/code</span><span>Research</span></div>
      <label>Public contribution URL</label>
      <input value={contributionUrl} onChange={e => setContributionUrl(e.target.value)} placeholder="https://x.com/... or https://youtube.com/..." />
      <label>What does it help people understand?</label>
      <input value={topic} onChange={e => setTopic(e.target.value)} placeholder="Example: how Technocore DIDs work" />
    </div></div></section>

    <section className="card"><div className="stephead"><div className="number">4</div><div className="grow">
      <h2>Record your contribution</h2>
      <p>This sends the contribution announcement to the <b>technocore</b> room using the same DID.</p>
      <div className="preview">I published a Technocore contribution: {contributionUrl || "PUBLIC_CONTRIBUTION_URL"}. It helps people understand {topic || "YOUR_SPECIFIC_TOPIC"}.</div>
      <button className="primary" disabled={!identity || busy || !contributionUrl || !topic} onClick={announceContribution}>Record Contribution</button>
      {state.contribution && <div className="output show good">Room: {state.contribution.room}{"\n"}Sequence: {state.contribution.seq ?? "—"}{"\n"}DID: {identity?.did}{"\n"}URL: {state.contribution.url}</div>}
    </div></div></section>

    <section className="card"><div className="stephead"><div className="number">5</div><div className="grow">
      <h2>Save & share your evidence</h2>
      <div className="actions">
        <button className="primary" disabled={!state.contribution} onClick={copySharePost}>Copy X Post</button>
        <button className="secondary" disabled={!identity} onClick={copyEvidence}>Copy Full Evidence</button>
      </div>
      <pre className="output show">{JSON.stringify(evidence, null, 2)}</pre>
    </div></div></section>

    <section className="card"><div className="stephead"><div className="number">+</div><div className="grow">
      <h2>Optional: Git proof</h2>
      <p>Only for contributions stored in Git.</p>
      <label>Full Git commit hash</label>
      <input value={commit} onChange={e => setCommit(e.target.value)} placeholder="40 or 64 character commit hash" />
      <button className="secondary" disabled={!identity || !commit || !contributionUrl || busy} onClick={createProof}>Create & Download Proof JSON</button>
    </div></div></section>

    <section className="card"><div className="stephead"><div className="number">+</div><div className="grow">
      <h2>Optional: read rooms</h2>
      <div className="actions">
        <button className="secondary" onClick={() => readRoom("lobby")} disabled={busy}>Read Lobby</button>
        <button className="secondary" onClick={() => readRoom("technocore")} disabled={busy}>Read Technocore</button>
      </div>
      {roomOutput && <pre className="output show">{roomOutput}</pre>}
    </div></div></section>

    <div className="footer">Completing this workflow documents participation; it does not guarantee any allocation.</div>
  </main>;
}
