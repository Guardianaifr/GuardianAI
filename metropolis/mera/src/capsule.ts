import type { PasskeySecretVault } from '@category-labs/mera';
import { parseSecretVault } from '@category-labs/mera';

/**
 * A capsule is everything a second device needs to pick up an agent, minus anything secret:
 * the agent id, its sealed memory (ciphertext) and an optional credential vault (ciphertext).
 * It travels in the URL fragment (#c=...), which browsers never send to a server.
 * Without the operator's passkey it is useless: the keys are re-derived from the passkey, never shipped.
 */
export type Capsule = {
  v: 1;
  agent: string;
  /** Hex DID shown on the first device, so the second device can prove it derived the same identity. */
  did?: string;
  memory?: { c: string; iv: string; aad: string };
  vault?: PasskeySecretVault;
};

export function b64url(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function fromB64url(text: string): Uint8Array<ArrayBuffer> {
  if (!/^[A-Za-z0-9_-]*$/.test(text)) throw new Error('not base64url');
  const s = atob(text.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((text.length + 3) % 4));
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

const AGENT_ID = /^[A-Za-z0-9:._-]{1,96}$/;

export function encodeCapsule(capsule: Capsule): string {
  return b64url(new TextEncoder().encode(JSON.stringify(capsule)));
}

/** Parses an untrusted capsule (it arrives in a link). Throws on anything unexpected. */
export function decodeCapsule(text: string): Capsule {
  if (text.length > 8192) throw new Error('capsule too large');
  const raw = JSON.parse(new TextDecoder().decode(fromB64url(text)));
  if (!raw || typeof raw !== 'object' || raw.v !== 1) throw new Error('unsupported capsule');
  if (typeof raw.agent !== 'string' || !AGENT_ID.test(raw.agent)) throw new Error('bad agent id');
  const out: Capsule = { v: 1, agent: raw.agent };
  if (raw.did !== undefined) {
    if (typeof raw.did !== 'string' || !/^did:guardian:ed25519:[0-9a-f]{64}$/.test(raw.did)) throw new Error('bad did');
    out.did = raw.did;
  }
  if (raw.memory !== undefined) {
    const m = raw.memory;
    if (!m || typeof m.c !== 'string' || typeof m.iv !== 'string' || typeof m.aad !== 'string') throw new Error('bad memory');
    fromB64url(m.c);
    if (fromB64url(m.iv).length !== 12) throw new Error('bad iv');
    if (!m.aad.startsWith(`${raw.agent}:`) || m.aad.length > 256) throw new Error('bad aad');
    out.memory = { c: m.c, iv: m.iv, aad: m.aad };
  }
  if (raw.vault !== undefined) out.vault = parseSecretVault(raw.vault);
  return out;
}

export function isValidAgentId(id: string): boolean {
  return AGENT_ID.test(id);
}
