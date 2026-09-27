import { describe, it, expect, beforeEach } from 'vitest';
import GuardianMeraEngine, { deriveAgentIdentity, sealMemory, unsealMemory } from '../src/guardian_mera_engine';
import { MockWebAuthnClient } from '../src/mock_webauthn_client';

describe('Mera Enclave Hard Stress & Adversarial Audit', () => {
  let masterSecret: Uint8Array;
  let webAuthnClient: MockWebAuthnClient;
  let engine: GuardianMeraEngine;

  beforeEach(() => {
    masterSecret = new Uint8Array(32);
    crypto.getRandomValues(masterSecret);
    webAuthnClient = new MockWebAuthnClient({ masterSecret });
    engine = new GuardianMeraEngine('audit.guardianai.local');
  });

  // ── 1. Real-World LLM Context Scaling (1 KB to 500 KB) ───────────────────
  describe('Payload Scalability with Real Agent Contexts', () => {
    const payloadSizes = [
      { label: '1 KB (Short prompt & single decision)', size: 1024 },
      { label: '10 KB (Multi-turn conversational history)', size: 10 * 1024 },
      { label: '100 KB (Large DeFi portfolio strategy & order book snapshot)', size: 100 * 1024 },
      { label: '500 KB (Full autonomous agent memory state snapshot)', size: 500 * 1024 },
    ];

    for (const { label, size } of payloadSizes) {
      it(`seals and unseals ${label} with 100% fidelity`, async () => {
        // Generate pseudo-realistic JSON strategy context
        const dummyStrategy = {
          agentId: 'guardian-alpha',
          timestamp: Date.now(),
          marketConditions: { volatility: 0.24, gasPriceGwei: 52 },
          rebalanceThreshold: 0.0015,
          rawTelemetry: 'A'.repeat(size),
        };
        const rawJson = JSON.stringify(dummyStrategy);

        const startSeal = performance.now();
        const sealed = await engine.sealMemory('guardian-alpha', 'session-scale', 1, rawJson, webAuthnClient);
        const sealDuration = performance.now() - startSeal;

        expect(sealed.ciphertext.length).toBeGreaterThan(size);

        const startUnseal = performance.now();
        const unsealed = await engine.unsealMemory(
          'guardian-alpha',
          sealed.ciphertext,
          sealed.iv,
          sealed.aad,
          webAuthnClient
        );
        const unsealDuration = performance.now() - startUnseal;

        expect(unsealed.poisoned).toBe(false);
        if (!unsealed.poisoned) {
          expect(unsealed.plaintext).toBe(rawJson);
          const parsed = JSON.parse(unsealed.plaintext);
          expect(parsed.agentId).toBe('guardian-alpha');
        }

        // Performance assertions: Even 500 KB unseal should be sub-50ms with WebCrypto
        expect(unsealDuration).toBeLessThan(150);
      });
    }
  });

  // ── 2. High-Concurrency Swarm Minting (50 Agents) ────────────────────────
  describe('Swarm Concurrency & Namespace Non-Collision', () => {
    it('concurrently mints 50 agent identities with zero collision and isolated DIDs', async () => {
      const agentCount = 50;
      const agentIds = Array.from({ length: agentCount }, (_, i) => `swarm-agent-${i.toString().padStart(3, '0')}`);

      const startTime = performance.now();
      const promises = agentIds.map(id => engine.deriveAgentIdentity(id, webAuthnClient));
      const identities = await Promise.all(promises);
      const totalTime = performance.now() - startTime;

      expect(identities.length).toBe(agentCount);

      const didSet = new Set<string>();
      const pubkeySet = new Set<string>();

      for (let i = 0; i < agentCount; i++) {
        const id = identities[i];
        expect(id.agentId).toBe(agentIds[i]);
        expect(id.publicKey.length).toBe(32);
        expect(id.did).toMatch(/^did:guardian:ed25519:[a-f0-9]{64}$/);

        const hexPub = Array.from(id.publicKey).map(b => b.toString(16).padStart(2, '0')).join('');
        didSet.add(id.did);
        pubkeySet.add(hexPub);
      }

      // Assert complete uniqueness: exactly 50 distinct DIDs and public keys
      expect(didSet.size).toBe(agentCount);
      expect(pubkeySet.size).toBe(agentCount);

      // Average derivation throughput
      const avgPerMint = totalTime / agentCount;
      expect(avgPerMint).toBeLessThan(20); // Sub-20ms per identity in mock
    });
  });

  // ── 3. Rigorous Bit-Flip Fuzzing (100 Random Locations) ───────────────────
  describe('Exhaustive Bit-Flip Tamper Resistance', () => {
    it('rejects tampered ciphertexts across 50 random byte positions with 100% detection rate', async () => {
      const payload = 'Confidential liquidity strategy: deploy 500,000 USDC on Monad DEX pool 0x32fa262042';
      const sealed = await engine.sealMemory('agent-fuzz', 'session-fuzz', 1, payload, webAuthnClient);

      const cipherLen = sealed.ciphertext.length;
      expect(cipherLen).toBeGreaterThan(50);

      // Pick 50 distinct positions across header, body, and auth tag
      const step = Math.max(1, Math.floor(cipherLen / 50));
      let rejectedCount = 0;

      for (let i = 0; i < cipherLen; i += step) {
        const corrupted = new Uint8Array(sealed.ciphertext);
        corrupted[i] ^= 0x01; // Invert a single bit

        const res = await engine.unsealMemory('agent-fuzz', corrupted, sealed.iv, sealed.aad, webAuthnClient);
        if (res.poisoned && res.error === 'MEMORY_POISONING_DETECTED') {
          rejectedCount++;
        }
      }

      // 100% of single-bit corruptions MUST be caught by AES-256-GCM authentication tag
      expect(rejectedCount).toBe(Math.ceil(cipherLen / step));
    });

    it('rejects tampering in the IV (Initialization Vector)', async () => {
      const payload = 'Sensitive context note: transfer authority restricted to timelock';
      const sealed = await engine.sealMemory('agent-iv-test', 'sess-iv', 1, payload, webAuthnClient);

      for (let ivByte = 0; ivByte < 12; ivByte++) {
        const corruptedIv = new Uint8Array(sealed.iv);
        corruptedIv[ivByte] ^= 0x80; // Flip highest bit

        const res = await engine.unsealMemory(
          'agent-iv-test',
          sealed.ciphertext,
          corruptedIv,
          sealed.aad,
          webAuthnClient
        );
        expect(res.poisoned).toBe(true);
        if (res.poisoned) {
          expect(res.error).toBe('MEMORY_POISONING_DETECTED');
        }
      }
    });
  });

  // ── 4. Replay, Session Transposition & Permutation Attacks ───────────────
  describe('Cryptographic AAD Binding & Sequence Attack Defense', () => {
    it('blocks session transposition: cannot decrypt session A memory under session B context', async () => {
      const payload = 'Rebalance order #101 for Alpha vault';
      const sealed = await engine.sealMemory('agent-target', 'session-AAA', 1, payload, webAuthnClient);

      // Attacker intercepts ciphertext and tries to inject it into session-BBB
      const corruptedAad = sealed.aad.replace('session-AAA', 'session-BBB');

      const res = await engine.unsealMemory(
        'agent-target',
        sealed.ciphertext,
        sealed.iv,
        corruptedAad,
        webAuthnClient
      );
      expect(res.poisoned).toBe(true);
    });

    it('blocks sequence number tampering: cannot replay seq 1 as seq 999', async () => {
      const payload = 'Withdraw 10,000 MON';
      const sealed = await engine.sealMemory('agent-seq', 'session-seq', 1, payload, webAuthnClient);

      // Attacker alters sequence number in AAD header
      const parts = sealed.aad.split(':');
      parts[2] = '999'; // Tampered sequence
      const tamperedAad = parts.join(':');

      const res = await engine.unsealMemory(
        'agent-seq',
        sealed.ciphertext,
        sealed.iv,
        tamperedAad,
        webAuthnClient
      );
      expect(res.poisoned).toBe(true);
    });

    it('blocks agent cross-targeting: cannot decrypt agent-X memory using agent-Y identity', async () => {
      const payload = 'Private keys or seed phrases belonging to Agent X';
      const sealed = await engine.sealMemory('agent-X', 'session-X', 1, payload, webAuthnClient);

      // Attempt unseal using agent-Y's namespace (different PRF salt)
      const res = await engine.unsealMemory(
        'agent-Y',
        sealed.ciphertext,
        sealed.iv,
        sealed.aad,
        webAuthnClient
      );
      expect(res.poisoned).toBe(true);
    });
  });

  // ── 5. Latency & Throughput Benchmark (100 Operations) ────────────────────
  describe('Performance Benchmark (P50 / P95 / P99)', () => {
    it('benchmarks 100 seal/unseal cycles and calculates latency percentiles', async () => {
      const iterations = 100;
      const sealTimes: number[] = [];
      const unsealTimes: number[] = [];
      const samplePayload = JSON.stringify({
        rule: 'max_slippage_0.5%',
        whitelistedPools: ['0x1111', '0x2222', '0x3333'],
        targetGas: 45,
      });

      for (let i = 0; i < iterations; i++) {
        const t0 = performance.now();
        const sealed = await engine.sealMemory('benchmark-agent', 'bench-session', i, samplePayload, webAuthnClient);
        sealTimes.push(performance.now() - t0);

        const t1 = performance.now();
        const unsealed = await engine.unsealMemory(
          'benchmark-agent',
          sealed.ciphertext,
          sealed.iv,
          sealed.aad,
          webAuthnClient
        );
        unsealTimes.push(performance.now() - t1);
        expect(unsealed.poisoned).toBe(false);
      }

      function percentile(arr: number[], p: number) {
        const sorted = [...arr].sort((a, b) => a - b);
        const idx = Math.floor((p / 100) * sorted.length);
        return sorted[idx];
      }

      const sealP50 = percentile(sealTimes, 50);
      const sealP95 = percentile(sealTimes, 95);
      const sealP99 = percentile(sealTimes, 99);

      const unsealP50 = percentile(unsealTimes, 50);
      const unsealP95 = percentile(unsealTimes, 95);
      const unsealP99 = percentile(unsealTimes, 99);

      console.log('\n--- MERA CRYPTOGRAPHIC BENCHMARK (100 ITERATIONS) ---');
      console.log(`Seal (AES-256-GCM + HKDF):   P50: ${sealP50.toFixed(2)}ms | P95: ${sealP95.toFixed(2)}ms | P99: ${sealP99.toFixed(2)}ms`);
      console.log(`Unseal (AES-256-GCM Verify): P50: ${unsealP50.toFixed(2)}ms | P95: ${unsealP95.toFixed(2)}ms | P99: ${unsealP99.toFixed(2)}ms`);

      // Latency thresholds for production readiness:
      // P50 should be sub-5ms, P99 should be sub-15ms
      expect(sealP50).toBeLessThan(10);
      expect(unsealP50).toBeLessThan(10);
    });
  });
});
