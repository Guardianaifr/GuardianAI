import { getPasskeyPrfOutput, createEd25519SigningSession, isMeraError } from '@category-labs/mera';
import type { WebAuthnClient } from '@category-labs/mera';

/**
 * GuardianAI x Mera: one operator passkey, one PRF salt per job.
 *
 *   guardianai:v1:agent:identity:<agentId>  -> Ed25519 key (agent DID, signs agent cards)   [derivation]
 *   guardianai:v1:agent:memory:<agentId>    -> HKDF -> AES-256-GCM key (agent memory)       [encryption]
 *   random salt per secret (Mera vault)     -> AES-256-GCM key (credential vault)           [encryption]
 *
 * Nothing derived here is written anywhere: private keys live in a Mera signing session that is
 * ended (zeroed) before the function returns, AES keys are non-extractable WebCrypto keys, and raw
 * PRF outputs are zeroed after use. Only public keys, ciphertext and signatures leave this module.
 *
 * `webAuthnClient` is optional: omit it in a browser and Mera uses `navigator.credentials`
 * (a real passkey). Tests pass MockWebAuthnClient.
 */

export const IDENTITY_NAMESPACE = 'guardianai:v1:agent:identity:';
export const MEMORY_NAMESPACE = 'guardianai:v1:agent:memory:';
const MEMORY_HKDF_INFO = 'guardianai:v1:encrypt:memory';

export type SealedMemory = {
  ciphertext: Uint8Array;
  iv: Uint8Array;
  aad: string;
  timestamp: number;
};

export type AgentIdentity = {
  publicKey: Uint8Array;
  did: string;
  agentId: string;
};

export type UnsealResult =
  | { plaintext: string; poisoned: false }
  | { plaintext: null; poisoned: true; error: 'MEMORY_POISONING_DETECTED' }
  /** The passkey ceremony failed or was cancelled: nothing was decrypted, but nothing was tampered with either. */
  | { plaintext: null; poisoned: false; error: 'PASSKEY_UNAVAILABLE'; detail: string };

/** A signed statement: "the operator's passkey authorizes <agent> to use <wallet> until <expires>". */
export type AgentCard = {
  version: 1;
  agent_id: string;
  wallet: string;
  expires_at: number;
  did: string;
  signature: string;
};

export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

export async function namespaceSalt(label: string): Promise<Uint8Array<ArrayBuffer>> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(label)));
}

async function prfFor(
  label: string,
  webAuthnClient: WebAuthnClient | undefined,
  rpId: string,
  credentialId?: string,
) {
  return getPasskeyPrfOutput({
    rpId,
    prfSalt: await namespaceSalt(label),
    ...(webAuthnClient ? { webAuthnClient } : {}),
    ...(credentialId ? { credential: { credentialId } } : {}),
  });
}

async function memoryKey(prfOutput: Uint8Array<ArrayBuffer>, usage: 'encrypt' | 'decrypt'): Promise<CryptoKey> {
  const baseKey = await crypto.subtle.importKey('raw', prfOutput, 'HKDF', false, ['deriveKey']);
  prfOutput.fill(0);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: new TextEncoder().encode(MEMORY_HKDF_INFO) },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    [usage],
  );
}

export async function deriveAgentIdentity(
  agentId: string,
  webAuthnClient?: WebAuthnClient,
  rpId: string = 'guardianai.localhost',
  credentialId?: string
): Promise<{ identity: AgentIdentity, credentialId: string | null }> {
  const prf = await prfFor(IDENTITY_NAMESPACE + agentId, webAuthnClient, rpId, credentialId);
  const session = createEd25519SigningSession({ privateKey: prf.prfOutput });
  prf.prfOutput.fill(0);
  const publicKey = new Uint8Array(session.publicKey);
  session.end();
  return {
    identity: { publicKey, did: `did:guardian:ed25519:${toHex(publicKey)}`, agentId },
    credentialId: prf.credentialId || credentialId || null,
  };
}

/** The exact bytes an agent card signs. The relay (guardian/relayer/agent_card.py) rebuilds the same string. */
export function agentCardMessage(agentId: string, wallet: string, expiresAt: number): Uint8Array {
  return new TextEncoder().encode(
    `GuardianAI agent card v1\nagent: ${agentId}\nwallet: ${wallet.toLowerCase()}\nexpires: ${expiresAt}`,
  );
}

/**
 * Signs an agent card with the agent's passkey-derived Ed25519 key (identity namespace).
 * This is not a blockchain transaction: it proves to the GuardianAI relay that the operator
 * authorized this agent id for this wallet.
 */
export async function signAgentCard(
  agentId: string,
  wallet: string,
  expiresAt: number,
  webAuthnClient?: WebAuthnClient,
  rpId: string = 'guardianai.localhost',
  credentialId?: string,
): Promise<{ card: AgentCard, credentialId: string | null }> {
  if (!/^0x[0-9a-fA-F]{40}$/.test(wallet)) throw new Error('wallet must be a 0x-prefixed 20-byte address');
  if (!Number.isInteger(expiresAt) || expiresAt <= 0) throw new Error('expiresAt must be unix seconds');
  const prf = await prfFor(IDENTITY_NAMESPACE + agentId, webAuthnClient, rpId, credentialId);
  const session = createEd25519SigningSession({ privateKey: prf.prfOutput });
  prf.prfOutput.fill(0);
  try {
    const signature = await session.signMessage(agentCardMessage(agentId, wallet, expiresAt));
    return {
      card: {
        version: 1,
        agent_id: agentId,
        wallet: wallet.toLowerCase(),
        expires_at: expiresAt,
        did: `did:guardian:ed25519:${toHex(session.publicKey)}`,
        signature: toHex(signature),
      },
      credentialId: prf.credentialId || credentialId || null,
    };
  } finally {
    session.end();
  }
}

export async function sealMemory(
  agentId: string,
  sessionId: string,
  seqNo: number,
  plaintext: string,
  webAuthnClient?: WebAuthnClient,
  rpId: string = 'guardianai.localhost',
  credentialId?: string
): Promise<{ sealed: SealedMemory, credentialId: string | null }> {
  const prf = await prfFor(MEMORY_NAMESPACE + agentId, webAuthnClient, rpId, credentialId);
  const resolvedCredentialId = prf.credentialId || credentialId || null;
  const aesKey = await memoryKey(prf.prfOutput, 'encrypt');

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const timestamp = Date.now();
  const aad = `${agentId}:${sessionId}:${seqNo}:${timestamp}`;
  const ciphertextBuf = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: new TextEncoder().encode(aad) },
    aesKey,
    new TextEncoder().encode(plaintext),
  );

  return {
    sealed: { ciphertext: new Uint8Array(ciphertextBuf), iv, aad, timestamp },
    credentialId: resolvedCredentialId,
  };
}

export async function unsealMemory(
  agentId: string,
  ciphertext: Uint8Array,
  iv: Uint8Array,
  aad: string,
  webAuthnClient?: WebAuthnClient,
  rpId: string = 'guardianai.localhost',
  credentialId?: string
): Promise<UnsealResult> {
  let prf;
  try {
    prf = await prfFor(MEMORY_NAMESPACE + agentId, webAuthnClient, rpId, credentialId);
  } catch (e) {
    // A cancelled or unsupported passkey prompt is not evidence of tampering.
    const detail = isMeraError(e) ? `${e.code}: ${e.message}` : String((e as Error)?.message ?? e);
    return { plaintext: null, poisoned: false, error: 'PASSKEY_UNAVAILABLE', detail };
  }
  const aesKey = await memoryKey(prf.prfOutput, 'decrypt');
  try {
    const plaintextBuf = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: iv as Uint8Array<ArrayBuffer>, additionalData: new TextEncoder().encode(aad) },
      aesKey,
      ciphertext as Uint8Array<ArrayBuffer>,
    );
    return { plaintext: new TextDecoder().decode(plaintextBuf), poisoned: false };
  } catch {
    // GCM tag mismatch: ciphertext, IV or AAD was changed (or a different passkey was used).
    return { plaintext: null, poisoned: true, error: 'MEMORY_POISONING_DETECTED' };
  }
}

export default class GuardianMeraEngine {
  private credentialId: string | null = null;
  private rpId: string;

  constructor(rpId: string = 'guardianai.localhost') {
    this.rpId = rpId;
  }

  setCredentialId(id: string) {
    this.credentialId = id;
  }

  getCredentialId(): string | null {
    return this.credentialId;
  }

  private remember(credentialId: string | null) {
    if (credentialId && !this.credentialId) this.credentialId = credentialId;
  }

  async deriveAgentIdentity(agentId: string, webAuthnClient?: WebAuthnClient): Promise<AgentIdentity> {
    const { identity, credentialId } = await deriveAgentIdentity(agentId, webAuthnClient, this.rpId, this.credentialId ?? undefined);
    this.remember(credentialId);
    return identity;
  }

  async signAgentCard(agentId: string, wallet: string, expiresAt: number, webAuthnClient?: WebAuthnClient): Promise<AgentCard> {
    const { card, credentialId } = await signAgentCard(agentId, wallet, expiresAt, webAuthnClient, this.rpId, this.credentialId ?? undefined);
    this.remember(credentialId);
    return card;
  }

  async sealMemory(
    agentId: string,
    sessionId: string,
    seqNo: number,
    plaintext: string,
    webAuthnClient?: WebAuthnClient
  ): Promise<SealedMemory> {
    const { sealed, credentialId } = await sealMemory(agentId, sessionId, seqNo, plaintext, webAuthnClient, this.rpId, this.credentialId ?? undefined);
    this.remember(credentialId);
    return sealed;
  }

  async unsealMemory(
    agentId: string,
    ciphertext: Uint8Array,
    iv: Uint8Array,
    aad: string,
    webAuthnClient?: WebAuthnClient
  ): Promise<UnsealResult> {
    return unsealMemory(agentId, ciphertext, iv, aad, webAuthnClient, this.rpId, this.credentialId ?? undefined);
  }
}
