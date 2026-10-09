import { describe, it, expect } from 'vitest';
import { createPublicKey, verify } from 'node:crypto';
import { createSecretVaultWithExistingPasskey, decryptSecretVaultWithPasskey } from '@category-labs/mera';
import type { WebAuthnClient } from '@category-labs/mera';
import { deriveAgentIdentity, signAgentCard, agentCardMessage, sealMemory, unsealMemory } from '../src/guardian_mera_engine';
import { encodeCapsule, decodeCapsule, b64url, fromB64url } from '../src/capsule';
import { MockWebAuthnClient } from '../src/mock_webauthn_client';

const RP = 'test.localhost';
const masterBytes = (fill: number) => new Uint8Array(32).fill(fill);
const hexToBytes = (h: string) => Uint8Array.from(h.match(/../g)!.map(x => parseInt(x, 16)));

function ed25519Verify(pubHex: string, msg: Uint8Array, sigHex: string): boolean {
  const key = createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: Buffer.from(hexToBytes(pubHex)).toString('base64url') }, format: 'jwk' });
  return verify(null, msg, key, hexToBytes(sigHex));
}

describe('agent card (identity namespace)', () => {
  it('is signed by the same key as the agent DID and verifies with plain Ed25519', async () => {
    const client = new MockWebAuthnClient({ masterSecret: masterBytes(7) });
    const { identity } = await deriveAgentIdentity('treasury-agent', client, RP);
    const wallet = '0xCCb137694f2910c8Ec4883d108c989648019D335';
    const { card } = await signAgentCard('treasury-agent', wallet, 1_900_000_000, client, RP);
    expect(card.did).toBe(identity.did);
    expect(card.wallet).toBe(wallet.toLowerCase());
    const pub = card.did.split(':').pop()!;
    expect(ed25519Verify(pub, agentCardMessage('treasury-agent', wallet, 1_900_000_000), card.signature)).toBe(true);
    // Any edited field breaks the signature.
    expect(ed25519Verify(pub, agentCardMessage('treasury-agent', wallet, 1_900_000_001), card.signature)).toBe(false);
    expect(ed25519Verify(pub, agentCardMessage('other-agent', wallet, 1_900_000_000), card.signature)).toBe(false);
  });

  it('message format matches the relay verifier byte for byte', () => {
    expect(new TextDecoder().decode(agentCardMessage('a', '0xABCDEF0000000000000000000000000000000001', 5)))
      .toBe('GuardianAI agent card v1\nagent: a\nwallet: 0xabcdef0000000000000000000000000000000001\nexpires: 5');
  });

  it('rejects malformed wallets', async () => {
    const client = new MockWebAuthnClient({ masterSecret: masterBytes(7) });
    await expect(signAgentCard('a', 'not-an-address', 5, client, RP)).rejects.toThrow();
  });
});

describe('namespaces are isolated', () => {
  it('identity and memory salts give unrelated keys for the same agent', async () => {
    const client = new MockWebAuthnClient({ masterSecret: masterBytes(3) });
    const a = await deriveAgentIdentity('agent-x', client, RP);
    const b = await deriveAgentIdentity('agent-y', client, RP);
    expect(a.identity.did).not.toBe(b.identity.did);
    // Memory sealed for agent-x cannot be opened under agent-y's memory namespace.
    const { sealed } = await sealMemory('agent-x', 's', 1, 'hello', client, RP);
    const r = await unsealMemory('agent-y', sealed.ciphertext, sealed.iv, sealed.aad, client, RP);
    expect(r.poisoned).toBe(true);
  });
});

describe('unseal failure modes', () => {
  it('a cancelled passkey prompt is PASSKEY_UNAVAILABLE, not poisoning', async () => {
    const client = new MockWebAuthnClient({ masterSecret: masterBytes(9) });
    const { sealed } = await sealMemory('agent-1', 's', 1, 'hello', client, RP);
    const cancelling: WebAuthnClient = {
      createCredential: async () => { throw new DOMException('cancelled', 'NotAllowedError'); },
      getCredential: async () => { throw new DOMException('cancelled', 'NotAllowedError'); },
    } as unknown as WebAuthnClient;
    const r = await unsealMemory('agent-1', sealed.ciphertext, sealed.iv, sealed.aad, cancelling, RP);
    expect(r.poisoned).toBe(false);
    expect(r.plaintext).toBeNull();
    if (!r.poisoned && r.plaintext === null) expect(r.error).toBe('PASSKEY_UNAVAILABLE');
  });

  it('a different passkey cannot decrypt (treated as tampering)', async () => {
    const { sealed } = await sealMemory('agent-1', 's', 1, 'hello', new MockWebAuthnClient({ masterSecret: masterBytes(1) }), RP);
    const r = await unsealMemory('agent-1', sealed.ciphertext, sealed.iv, sealed.aad, new MockWebAuthnClient({ masterSecret: masterBytes(2) }), RP);
    expect(r.poisoned).toBe(true);
  });
});

describe('handoff capsule (cross-device link)', () => {
  it('round-trips DID, memory and a Mera vault, and the second device decrypts both', async () => {
    const deviceA = new MockWebAuthnClient({ masterSecret: masterBytes(5) });
    const { identity } = await deriveAgentIdentity('treasury-agent', deviceA, RP);
    const { sealed } = await sealMemory('treasury-agent', 'console', 1, 'pay only approved vendors', deviceA, RP);
    const vault = await createSecretVaultWithExistingPasskey({ rpId: RP, webAuthnClient: deviceA, secret: new TextEncoder().encode('sk-demo-123') });

    const link = encodeCapsule({
      v: 1, agent: 'treasury-agent', did: identity.did,
      memory: { c: b64url(sealed.ciphertext), iv: b64url(sealed.iv), aad: sealed.aad }, vault,
    });
    expect(link).not.toContain('sk-demo');

    const deviceB = new MockWebAuthnClient({ masterSecret: masterBytes(5) }); // same synced passkey
    const cap = decodeCapsule(link);
    expect((await deriveAgentIdentity(cap.agent, deviceB, RP)).identity.did).toBe(cap.did);
    const r = await unsealMemory(cap.agent, fromB64url(cap.memory!.c), fromB64url(cap.memory!.iv), cap.memory!.aad, deviceB, RP);
    expect(r.plaintext).toBe('pay only approved vendors');
    const s = await decryptSecretVaultWithPasskey({ rpId: RP, webAuthnClient: deviceB, vault: cap.vault! });
    expect(new TextDecoder().decode(s)).toBe('sk-demo-123');
  });

  it('rejects malformed or hostile capsules', () => {
    const enc = (o: unknown) => b64url(new TextEncoder().encode(JSON.stringify(o)));
    expect(() => decodeCapsule(enc({ v: 2, agent: 'a' }))).toThrow();
    expect(() => decodeCapsule(enc({ v: 1, agent: '<script>' }))).toThrow();
    expect(() => decodeCapsule(enc({ v: 1, agent: 'a', did: 'did:evil' }))).toThrow();
    expect(() => decodeCapsule(enc({ v: 1, agent: 'a', memory: { c: 'AA', iv: 'AA', aad: 'a:1' } }))).toThrow();
    expect(() => decodeCapsule(enc({ v: 1, agent: 'a', vault: { version: 1 } }))).toThrow();
    expect(() => decodeCapsule('!!!')).toThrow();
    expect(() => decodeCapsule('A'.repeat(9000))).toThrow();
  });
});
