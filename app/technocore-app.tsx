/* eslint-disable @typescript-eslint/no-explicit-any */
"use client";

import { useEffect, useState } from "react";
import { ed25519 } from "@noble/ed25519";

const STORAGE_KEY = "technocore-helper-v1";
const ROOM = "lobby";
const MAX_MESSAGE_CHARS = 4096;
const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

type Identity = {
  secret: string;
  did: string;
};

type StoredState = {
  identity?: Identity;
  contribution?: {
    url: string;
    commit: string;
    proof: Proof;
  };
  intro?: {
    seq?: number;
    nonce: string;
  };
};

type Proof = {
  schema: "technocore-contribution-proof-v1";
  did: string;
  artifact_url: string;
  commit: string;
  signature: string;
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
  return "1".repeat(zeros) + (out || "");
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
  const multicodec = new Uint8Array([0xed, 0x01, ...publicKey]);
  return `did:key:z${b58encode(multicodec)}`;
}

function normalizeMessage(text: string) {
  const normalized = Array.from(text).map(c => {
    const cp = c.codePointAt(0)!;
    // Mirror the upstream normalization for control/format/surrogate/line separator characters.
    if ((cp >= 0 && cp <= 31) || (cp >= 127 && cp <= 159) || cp === 0x2028 || cp === 0x2029 || (cp >= 0xe000 && cp <= 0xf8ff)) return " ";
    return c;
  }).join("").trim();

  if (!normalized) throw new Error("Message is empty after normalization.");
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

async function createIdentity(): Promise<Identity> {
  const secret = ed25519.utils.randomSecretKey();
  const pub = await ed25519.getPublicKeyAsync(secret);
  return { secret: bytesToB64(secret), did: didFromPublicKey(pub) };
}

async function signedMessage(identity: Identity, text: string) {
  const n = nonce();
  const normalized = normalizeMessage(text);
  const payload = `${ROOM}|${n}|${normalized}`;
  const signature = await signText(b64ToBytes(identity.secret), payload);
  return {
    did: identity.did,
    sig: signature,
    nonce: n,
    text: normalized,
  };
}

function canonicalProof(url: string, commit: string) {
  return JSON.stringify({
    artifact_url: url,
    commit: commit.toLowerCase(),
    schema: "technocore-contribution-v1",
  });
}

async function createProof(identity: Identity, url: string, commit: string): Promise<Proof> {
  const parsed = new URL(url);
  if (parsed.protocol !== "https:" || parsed.hash) throw new Error("Contribution URL must be an HTTPS URL without a fragment.");
  if (!/^(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$/.test(commit)) {
    throw new Error("Commit must be a complete 40- or 64-character hexadecimal revision.");
  }
  const signature = await signText(
    b64ToBytes(identity.secret),
    canonicalProof(url, commit)
  );
  return {
    schema: "technocore-contribution-proof-v1",
    did: identity.did,
    artifact_url: url,
    commit: commit.toLowerCase(),
    signature,
  };
}

function saveState(state: StoredState) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
}

function loadState(): StoredState {
  try {
    return JSON.parse(localStorage.getItem(STORAGE_KEY) || "{}");
  } catch {
    return {};
  }
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

function Output({ id, text, good }: { id: string; text: string; good?: boolean }) {
  if (!text) return null;
  return <pre id={id} className={`output show ${good ? "good" : "bad"}`}>{text}</pre>;
}

export default function TechnocoreApp() {
  const [state, setState] = useState<StoredState>({});
  const [introPass, setIntroPass] = useState("");
  const [introText, setIntroText] = useState("Hello from a new Technocore contributor. I am preparing a useful public resource for agents and developers.");
  const [introOut, setIntroOut] = useState("");
  const [introGood, setIntroGood] = useState(false);
  const [contributionUrl, setContributionUrl] = useState("");
  const [commit, setCommit] = useState("");
  const [proofOut, setProofOut] = useState("");
  const [proofGood, setProofGood] = useState(false);
  const [readOut, setReadOut] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    setState(loadState());
  }, []);

  const identity = state.identity;

  async function generate() {
    setBusy(true);
    setIntroOut("");
    try {
      if (identity) throw new Error("An identity already exists in this browser. We will not overwrite it.");
      const next = await createIdentity();
      const nextState = { ...state, identity: next };
      saveState(nextState);
      setState(nextState);
      setIntroGood(true);
      setIntroOut(`DID created successfully.\n\n${next.did}\n\nIMPORTANT: this private key is stored only in this browser. Export/back it up before clearing browser data.`);
    } catch (e: any) {
      setIntroGood(false);
      setIntroOut(e.message || "Could not create identity.");
    } finally {
      setBusy(false);
    }
  }

  async function sendIntroduction() {
    setBusy(true);
    setIntroOut("");
    try {
      if (!identity) throw new Error("Create your DID first.");
      const signed = await signedMessage(identity, introText);
      const result = await api("say", { room: ROOM, payload: signed });
      const seq = result?.posted?.seq;
      const nextState = { ...state, intro: { nonce: signed.nonce, seq } };
      saveState(nextState);
      setState(nextState);
      setIntroGood(true);
      setIntroOut(`Signed introduction published.\n\nDID: ${identity.did}\nRoom: ${ROOM}\nSequence: ${seq ?? "returned by server"}\nNonce: ${signed.nonce}\n\n${JSON.stringify(result, null, 2)}`);
    } catch (e: any) {
      setIntroGood(false);
      setIntroOut(e.message || "Could not publish introduction.");
    } finally {
      setBusy(false);
    }
  }

  async function makeProof() {
    setBusy(true);
    setProofOut("");
    try {
      if (!identity) throw new Error("Create your DID first.");
      const proof = await createProof(identity, contributionUrl.trim(), commit.trim());
      const nextState = { ...state, contribution: { url: contributionUrl.trim(), commit: commit.trim().toLowerCase(), proof } };
      saveState(nextState);
      setState(nextState);
      setProofGood(true);
      setProofOut(JSON.stringify(proof, null, 2));
    } catch (e: any) {
      setProofGood(false);
      setProofOut(e.message || "Could not create proof.");
    } finally {
      setBusy(false);
    }
  }

  async function announceContribution() {
    setBusy(true);
    setProofOut("");
    try {
      if (!identity) throw new Error("Create your DID first.");
      if (!contributionUrl.trim()) throw new Error("Enter your public contribution URL.");
      const text = `I published a Technocore contribution: ${contributionUrl.trim()}. Topic: ${"useful Technocore resource"}.`;
      const signed = await signedMessage(identity, text);
      const result = await api("say", { room: ROOM, payload: signed });
      setProofGood(true);
      setProofOut(`Contribution announcement published.\n\nDID: ${identity.did}\nRoom: ${ROOM}\nSequence: ${result?.posted?.seq ?? "returned by server"}\n\n${JSON.stringify(result, null, 2)}`);
    } catch (e: any) {
      setProofGood(false);
      setProofOut(e.message || "Could not announce contribution.");
    } finally {
      setBusy(false);
    }
  }

  async function readLobby() {
    setBusy(true);
    setReadOut("");
    try {
      const result = await api("read", { room: ROOM, limit: 20 });
      setReadOut(JSON.stringify(result, null, 2));
    } catch (e: any) {
      setReadOut(e.message || "Could not read the lobby.");
    } finally {
      setBusy(false);
    }
  }

  function clearBrowserIdentity() {
    if (!confirm("This removes the local identity from this browser. Make sure you have a backup first.")) return;
    localStorage.removeItem(STORAGE_KEY);
    setState({});
    setIntroOut("Local identity removed.");
    setIntroGood(false);
  }

  async function copy(value: string) {
    await navigator.clipboard.writeText(value);
  }

  const done1 = !!identity;
  const done2 = !!state.intro;
  const done3 = !!state.contribution;

  return (
    <main className="page">
      <section className="hero">
        <span className="eyebrow">TECHNOCORE • VERCEL APP</span>
        <h1>Complete your Technocore setup.</h1>
        <p>Generate your own DID, sign messages locally in your browser, announce a public contribution, and keep your private key out of the server.</p>
        <div className="notice">
          <b>Security:</b> your private key is generated and stored in this browser. Vercel only receives public signed payloads when you publish a message.
        </div>
        <div className="steps">
          <div className={`stepbar ${done1 ? "done" : ""}`} />
          <div className={`stepbar ${done2 ? "done" : ""}`} />
          <div className={`stepbar ${done3 ? "done" : ""}`} />
          <div className="stepbar" />
        </div>
      </section>

      <section className="card">
        <div className="stephead"><div className="number">1</div><div>
          <h2>Create your unique DID</h2>
          <p>Each user should create their own identity. The original starter requires an Ed25519 DID and warns not to copy another user's DID.</p>
          <div className="actions">
            <button className="primary" disabled={busy || !!identity} onClick={generate}>{identity ? "DID already created" : "Generate DID"}</button>
            {identity && <button className="secondary" onClick={() => copy(identity.did)}>Copy DID</button>}
          </div>
          {identity && <div className="output show good did">{identity.did}</div>}
          <Output id="r1" text={introOut} good={introGood} />
        </div></div>
      </section>

      <section className="card">
        <div className="stephead"><div className="number">2</div><div>
          <h2>Join Technocore</h2>
          <p>Send one signed introduction to the <b>lobby</b>. The exact signed payload follows the upstream format: <code>room|nonce|normalized-text</code>.</p>
          <textarea value={introText} onChange={e => setIntroText(e.target.value)} disabled={!identity || busy} />
          <div className="actions">
            <button className="primary" disabled={!identity || busy} onClick={sendIntroduction}>Send signed introduction</button>
          </div>
          <Output id="r2" text={introOut} good={introGood} />
        </div></div>
      </section>

      <section className="card">
        <div className="stephead"><div className="number">3</div><div>
          <h2>Create a useful public contribution</h2>
          <p>For most creators, the upstream guide recommends an X post/thread, video, article, graphic, translation, report, or tool. Git is optional for normal content.</p>
          <label>Public contribution URL</label>
          <input value={contributionUrl} onChange={e => setContributionUrl(e.target.value)} placeholder="https://x.com/... or https://youtube.com/..." disabled={!identity || busy} />
          <div className="grid">
            <div>
              <label>Git commit hash (optional for normal content)</label>
              <input value={commit} onChange={e => setCommit(e.target.value)} placeholder="40 or 64 hex characters" disabled={!identity || busy} />
            </div>
            <div className="notice" style={{marginTop:10}}>The signed proof below is only for Git-based contributions. You can still announce any public URL without a Git commit.</div>
          </div>
          <div className="actions">
            <button className="primary" disabled={!identity || busy || !commit.trim()} onClick={makeProof}>Create Git contribution proof</button>
            <button className="secondary" disabled={!identity || busy || !contributionUrl.trim()} onClick={announceContribution}>Announce public contribution</button>
          </div>
          <Output id="r3" text={proofOut} good={proofGood} />
        </div></div>
      </section>

      <section className="card">
        <div className="stephead"><div className="number">4</div><div>
          <h2>Save your evidence</h2>
          <p>Keep your DID, contribution URL, Technocore room, and returned sequence together. The starter guide recommends sharing this public evidence trail.</p>
          {identity ? (
            <div className="output show good did">{JSON.stringify({
              did: identity.did,
              room: ROOM,
              introduction_sequence: state.intro?.seq ?? null,
              contribution_url: state.contribution?.url ?? contributionUrl || null,
              contribution_proof: state.contribution?.proof ?? null
            }, null, 2)}</div>
          ) : <div className="notice">Create your DID first.</div>}
          <div className="actions">
            <button className="secondary" disabled={!identity} onClick={() => copy(JSON.stringify({
              did: identity?.did,
              room: ROOM,
              introduction_sequence: state.intro?.seq ?? null,
              contribution_url: state.contribution?.url ?? contributionUrl || null
            }, null, 2))}>Copy evidence</button>
            <button className="secondary" onClick={readLobby} disabled={busy}>Read latest lobby</button>
            {identity && <button className="secondary" onClick={clearBrowserIdentity}>Clear local identity</button>}
          </div>
          <Output id="r4" text={readOut} good />
        </div></div>
      </section>

      <div className="footer">
        Built as a browser UI around the public Technocore DID starter protocol. No private key is sent to Vercel. Rewards or airdrop eligibility are not guaranteed by completing this workflow.
      </div>
    </main>
  );
}
