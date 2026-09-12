import { describe, it, expect, beforeEach } from 'vitest';
import GuardianMeraEngine from '../src/guardian_mera_engine';
import { MockWebAuthnClient } from '../src/mock_webauthn_client';

describe('GuardianMeraEngine', () => {
  let masterSecret: Uint8Array;
  let webAuthnClient: MockWebAuthnClient;
  let engine: GuardianMeraEngine;

  beforeEach(() => {
    masterSecret = new Uint8Array(32);
    masterSecret.fill(1); // Fixed secret for testing
    webAuthnClient = new MockWebAuthnClient({ masterSecret });
    engine = new GuardianMeraEngine('test.localhost');
  });

  it('deriveAgentIdentity produces a valid Ed25519 public key and DID string', async () => {
    const identity = await engine.deriveAgentIdentity('agent-1', webAuthnClient);
    expect(identity.agentId).toBe('agent-1');
    expect(identity.publicKey.length).toBe(32);
    expect(identity.did).toMatch(/^did:guardian:ed25519:[a-f0-9]{64}$/);
  });

  it('Same agentId + same master secret -> identical identity', async () => {
    const identity1 = await engine.deriveAgentIdentity('agent-1', webAuthnClient);

    const engine2 = new GuardianMeraEngine('test.localhost');
    const webAuthnClient2 = new MockWebAuthnClient({ masterSecret }); // Simulated cross-device
    const identity2 = await engine2.deriveAgentIdentity('agent-1', webAuthnClient2);

    expect(identity1.did).toBe(identity2.did);
    expect(identity1.publicKey).toEqual(identity2.publicKey);
  });

  it('Different agentId -> different identity', async () => {
    const identity1 = await engine.deriveAgentIdentity('agent-1', webAuthnClient);
    const identity2 = await engine.deriveAgentIdentity('agent-2', webAuthnClient);

    expect(identity1.did).not.toBe(identity2.did);
  });

  it('sealMemory + unsealMemory round-trip succeeds', async () => {
    const plaintext = 'Secret memory content';
    const sealed = await engine.sealMemory('agent-1', 'session-1', 1, plaintext, webAuthnClient);

    const result = await engine.unsealMemory('agent-1', sealed.ciphertext, sealed.iv, sealed.aad, webAuthnClient);
    
    expect(result.poisoned).toBe(false);
    if (!result.poisoned) {
      expect(result.plaintext).toBe(plaintext);
    }
  });

  it('Tamper detection: flip 1 byte of ciphertext -> unsealMemory returns poisoned: true', async () => {
    const plaintext = 'Secret memory content';
    const sealed = await engine.sealMemory('agent-1', 'session-1', 1, plaintext, webAuthnClient);

    // Tamper ciphertext
    const tamperedCiphertext = new Uint8Array(sealed.ciphertext);
    tamperedCiphertext[0] ^= 0x01;

    const result = await engine.unsealMemory('agent-1', tamperedCiphertext, sealed.iv, sealed.aad, webAuthnClient);
    
    expect(result.poisoned).toBe(true);
    if (result.poisoned) {
      expect(result.error).toBe('MEMORY_POISONING_DETECTED');
    }
  });

  it('AAD mismatch detection: change the AAD string -> unsealMemory returns poisoned: true', async () => {
    const plaintext = 'Secret memory content';
    const sealed = await engine.sealMemory('agent-1', 'session-1', 1, plaintext, webAuthnClient);

    const tamperedAad = sealed.aad + 'tampered';

    const result = await engine.unsealMemory('agent-1', sealed.ciphertext, sealed.iv, tamperedAad, webAuthnClient);
    
    expect(result.poisoned).toBe(true);
    if (result.poisoned) {
      expect(result.error).toBe('MEMORY_POISONING_DETECTED');
    }
  });

  it('Different memory salt vs identity salt produces different PRF output', async () => {
    const encoder = new TextEncoder();
    const identitySalt = new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode('guardianai:v1:agent:identity:agent-1')));
    const memorySalt = new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode('guardianai:v1:agent:memory:agent-1')));

    const prfId = await webAuthnClient.getCredential({ rpId: 'test.localhost', challenge: new Uint8Array(32), prfSalt: identitySalt });
    const prfMem = await webAuthnClient.getCredential({ rpId: 'test.localhost', challenge: new Uint8Array(32), prfSalt: memorySalt });

    // Assert genuine mathematical salt separation (different salts produce distinct PRF outputs)
    expect(prfId.prfOutput).not.toEqual(prfMem.prfOutput);

    const identity = await engine.deriveAgentIdentity('agent-1', webAuthnClient);
    const sealed = await engine.sealMemory('agent-1', 'session-1', 1, 'text', webAuthnClient);
    
    expect(sealed.ciphertext.length).toBeGreaterThan(0);
    expect(identity.publicKey.length).toBe(32);
  });
});
