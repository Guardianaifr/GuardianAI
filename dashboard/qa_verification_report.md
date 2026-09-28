# QA Verification Report: GuardianAI Dashboard Interactions

This artifact serves as the Senior QA test report for all interactive testing actions on the GuardianAI dashboard. 

## 1. Global Pre-Flight Actions (`HomeTab.jsx`)

### A. Trigger Guarded Action (0.1 MON)
* **Trigger:** User clicks "Trigger Guarded Action" on the Home tab.
* **State Behavior:** The button immediately transitions to a loading state ("Executing on Monad...") with a spinning indicator. All other global test actions are disabled.
* **Payload Generation:** 
  * Injects a real-time `success` banner into the Home tab showing the mocked Monad testnet tx hash.
  * Injects an `ON-CHAIN ACTION` event into the live telemetry feed (visible in the Dashboard and Logs tabs).
  * Payload values: `riskScore: 5`, `target: 0x90Fd...EF60 (PolicyGuard)`, `latency: 3.2ms`.

### B. Test Rogue Action (10.0 MON)
* **Trigger:** User clicks "Test Rogue Action" on the Home tab.
* **State Behavior:** The button transitions to a loading state ("Engaging Containment...").
* **Payload Generation:**
  * Injects a critical `error` banner detailing that the off-chain Privy Policy Engine aborted the signature.
  * Injects a `POLICY CONTAINMENT` event into the live telemetry feed.
  * Payload values: `riskScore: 99`, `target: 0x9999...f08e (Unapproved EOA)`, `latency: 1.4ms`.

---

## 2. Agent-Specific Quick Actions (`AgentsTab.jsx`)

*Note: Previously, clicking one of these buttons caused ALL buttons across all agent cards to spin. This has been resolved by mapping the execution state to the specific `agent.id`.*

### A. Test Action (Per-Agent)
* **Trigger:** User clicks "Test Action" on a specific agent card (e.g., ElizaOS).
* **State Behavior:** **Only the button on the clicked agent card shows the spinner.** The buttons on the Mera and Passport agents become disabled to prevent transaction spam, but do not show false loading states.
* **Payload Generation:** Injects a global execution telemetry event, but specifically attributes it to the originating agent (`agent: 'eliza-monad-01'`).

### B. Test Rogue (Per-Agent)
* **Trigger:** User clicks "Test Rogue" on a specific agent card.
* **State Behavior:** **Only the clicked agent's button spins.**
* **Payload Generation:** Emits a global containment event with the rogue payload, mapped to the specific agent ID.

---

## 3. Protocol Primitive Simulation Probes (`AgentsTab.jsx` Sub-tabs)

*These probes use entirely isolated local state (`runningProbes` map) and do not trigger global execution state.*

### A. ElizaOS Autonomous Trader (Agent 1)
* **Simulate Prompt Injection:** Tests the middleware's ability to intercept an adversarial jailbreak before mempool broadcast. Emits a local error banner (`PROMPT INJECTION CONTAINED`) and pushes telemetry (`riskScore: 96`).
* **Simulate Valid Guarded Trade:** Tests an authorized swap under the 1.0 MON threshold. Emits a success banner and telemetry (`riskScore: 6`).

### B. Mera Cross-App Persistent Memory (Agent 2 - Track Idea #04)
* **Simulate Memory Tamper Probe:** Tests cross-app state corruption. The simulated RIP-7212 precompile rejects the tag. Emits local error banner (`MEMORY TAMPER CONTAINED`) and telemetry (`riskScore: 98`).
* **Simulate Passkey PRF Seal:** Simulates hardware-bound AES-256-GCM memory sealing. Emits success banner and telemetry (`riskScore: 3`).

### C. ERC-8004 Sovereign Identity (Agent 3)
* **Simulate Tombstone Revocation:** Simulates execution from a revoked agent passport. The `GuardianPolicyGuard` automatically reverts. Emits error banner (`PASSPORT TOMBSTONE HALT`) and telemetry (`riskScore: 100`).
* **Simulate Valid Identity Check:** Queries the Monad testnet registry. Emits success banner and telemetry (`riskScore: 2`, `tier: DIAMOND`).
