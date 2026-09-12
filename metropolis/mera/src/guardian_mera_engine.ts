import { getPasskeyPrfOutput, createEd25519SigningSession } from '@category-labs/mera';
import type { WebAuthnClient } from '@category-labs/mera';

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
  | { plaintext: null; poisoned: true; error: string };

function toHexString(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

export async function deriveAgentIdentity(
  agentId: string,
  webAuthnClient: WebAuthnClient,
  rpId: string = 'guardianai.localhost',
  credentialId?: string
): Promise<{ identity: AgentIdentity, credentialId: string | null }> {
  const encoder = new TextEncoder();
  const saltString = "guardianai:v1:agent:identity:" + agentId;
  const salt = new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(saltString)));

  const prfOutput = await getPasskeyPrfOutput({
    rpId,
    prfSalt: salt,
    webAuthnClient,
    ...(credentialId ? { credential: { credentialId } } : {})
  });

  const session = createEd25519SigningSession({ privateKey: prfOutput.prfOutput });
  const publicKey = session.publicKey;
  const did = `did:guardian:ed25519:${toHexString(publicKey)}`;
  
  session.end();
  // Overwrite the raw PRF output buffer in RAM for defense-in-depth
  prfOutput.prfOutput.fill(0);

  return {
    identity: { publicKey, did, agentId },
    credentialId: prfOutput.credentialId || credentialId || null
  };
}

export async function sealMemory(
  agentId: string,
  sessionId: string,
  seqNo: number,
  plaintext: string,
  webAuthnClient: WebAuthnClient,
  rpId: string = 'guardianai.localhost',
  credentialId?: string
): Promise<{ sealed: SealedMemory, credentialId: string | null }> {
  const encoder = new TextEncoder();
  const saltString = "guardianai:v1:agent:memory:" + agentId;
  const salt = new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(saltString)));

  const prfOutput = await getPasskeyPrfOutput({
    rpId,
    prfSalt: salt,
    webAuthnClient,
    ...(credentialId ? { credential: { credentialId } } : {})
  });

  const baseKey = await crypto.subtle.importKey(
    'raw',
    prfOutput.prfOutput,
    'HKDF',
    false,
    ['deriveKey']
  );
  // Zero raw PRF buffer in RAM once imported into WebCrypto
  prfOutput.prfOutput.fill(0);

  const aesKey = await crypto.subtle.deriveKey(
    { 
      name: 'HKDF', 
      hash: 'SHA-256', 
      salt: new Uint8Array(32), 
      info: encoder.encode('guardianai:v1:encrypt:memory') 
    },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt']
  );

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const timestamp = Date.now();
  const aadString = `${agentId}:${sessionId}:${seqNo}:${timestamp}`;
  const aad = encoder.encode(aadString);

  const ciphertextBuf = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv, additionalData: aad },
    aesKey,
    encoder.encode(plaintext)
  );

  return {
    sealed: {
      ciphertext: new Uint8Array(ciphertextBuf),
      iv,
      aad: aadString,
      timestamp
    },
    credentialId: prfOutput.credentialId || credentialId || null
  };
}

export async function unsealMemory(
  agentId: string,
  ciphertext: Uint8Array,
  iv: Uint8Array,
  aad: string,
  webAuthnClient: WebAuthnClient,
  rpId: string = 'guardianai.localhost',
  credentialId?: string
): Promise<UnsealResult> {
  const encoder = new TextEncoder();
  const saltString = "guardianai:v1:agent:memory:" + agentId;
  const salt = new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(saltString)));

  let prfOutput;
  try {
    prfOutput = await getPasskeyPrfOutput({
      rpId,
      prfSalt: salt,
      webAuthnClient,
      ...(credentialId ? { credential: { credentialId } } : {})
    });
  } catch (authError: any) {
    return { 
      plaintext: null, 
      poisoned: true, 
      error: authError?.message?.includes('PRF') ? 'AUTHENTICATOR_ERROR' : 'MEMORY_POISONING_DETECTED' 
    };
  }

  const baseKey = await crypto.subtle.importKey(
    'raw',
    prfOutput.prfOutput as any,
    'HKDF',
    false,
    ['deriveKey']
  );
  // Zero raw PRF buffer in RAM once imported into WebCrypto
  prfOutput.prfOutput.fill(0);

  const aesKey = await crypto.subtle.deriveKey(
    { 
      name: 'HKDF', 
      hash: 'SHA-256', 
      salt: new Uint8Array(32), 
      info: encoder.encode('guardianai:v1:encrypt:memory') 
    },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );

  try {
    const plaintextBuf = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: iv as any, additionalData: encoder.encode(aad) },
      aesKey,
      ciphertext as any
    );

    const decoder = new TextDecoder();
    return { plaintext: decoder.decode(plaintextBuf), poisoned: false };
  } catch (error) {
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

  async deriveAgentIdentity(agentId: string, webAuthnClient: WebAuthnClient): Promise<AgentIdentity> {
    const { identity, credentialId } = await deriveAgentIdentity(agentId, webAuthnClient, this.rpId, this.credentialId ?? undefined);
    if (credentialId && !this.credentialId) {
      this.credentialId = credentialId;
    }
    return identity;
  }

  async sealMemory(
    agentId: string,
    sessionId: string,
    seqNo: number,
    plaintext: string,
    webAuthnClient: WebAuthnClient
  ): Promise<SealedMemory> {
    const { sealed, credentialId } = await sealMemory(agentId, sessionId, seqNo, plaintext, webAuthnClient, this.rpId, this.credentialId ?? undefined);
    if (credentialId && !this.credentialId) {
      this.credentialId = credentialId;
    }
    return sealed;
  }

  async unsealMemory(
    agentId: string,
    ciphertext: Uint8Array,
    iv: Uint8Array,
    aad: string,
    webAuthnClient: WebAuthnClient
  ): Promise<UnsealResult> {
    return unsealMemory(agentId, ciphertext, iv, aad, webAuthnClient, this.rpId, this.credentialId ?? undefined);
  }
}
