# @guardianai/middleware

> **Drop-in AI Agent Web3 Security Middleware for Monad Testnet & EVM**  
> Cryptographic firewall intercepting transactions between AI Agents (ElizaOS, LangChain, Viem) and the Monad RPC.

---

## Overview

AI agents with on-chain execution capabilities are vulnerable to **prompt injection attacks**, **memory-poisoning exploits** (such as the Princeton/Sentient ElizaOS exploit), and **unauthorized wallet drains**.

`@guardianai/middleware` provides an automatic client-side interceptor that:
1. **Scans Prompts & Memory:** Detects jailbreaks, prompt injections, and adversarial overrides before actions execute.
2. **Decodes Pre-Flight Calldata:** Inspects target contract addresses, function selectors (ERC-20, Uniswap, native transfers), and parameters.
3. **Requests EIP-712 Attestation:** Contacts Guardian's sub-second attestation relayer (`<40ms` latency).
4. **Wraps Approved Transactions:** Re-routes transactions through [`GuardianPolicyGuard`](https://testnet.monadscan.com/address/0xa0ae75AaaB1c05D49fd5D15a0a95e0171aEDbB7d) (`0xa0ae...bB7d`) on Monad Testnet (`0x3cb7461c`).
5. **Strictly Fails Closed:** If an attestation is rejected or the relayer is unreachable, execution halts immediately with `GuardianSecurityError`—un-attested transactions never reach the blockchain.

---

## 0. ElizaOS 1.x agent with a guarded wallet (recommended)

The money lives in a **GuardianAgentWallet** on Monad (create one in the
[GuardianAI console](https://aiguardian.dev/explorer/?view=console) or with `examples/eliza-agent/setup.mjs`).
The agent key only pays gas. Every payment needs a GuardianAI approval and is re-checked by the contract.

```ts
import { guardianPlugin } from "@guardianai/middleware/elizaos";

plugins: [sqlPlugin, groqPlugin, bootstrapPlugin, guardianPlugin]
settings: { GUARDIAN_AGENT_PRIVATE_KEY, GUARDIAN_WALLET, GUARDIAN_OWNER }
```

* **`GUARDED_PAYMENT` action** — the agent's only way to move money: memory guard over the request *and* recent
  messages → GuardianAI relay approval → on-chain dry run → send from the agent key.
* **`GUARDIAN_WALLET` provider** — tells the model which wallet it pays from and its balance.
* Framework-free client: `GuardedWalletClient` (`@guardianai/middleware/guarded-wallet`) for any signer.

Verified with a real ElizaOS 1.7.2 agent on Groq against Monad testnet: honest invoice paid (mined), prompt
injection and memory poisoning blocked before any request, scam-list destination refused by the relay (risk 100),
Chainlink-flagged destination refused by the wallet (`FlaggedDestination`) — including when the LLM itself chose
to obey the attacker. Runnable: [`examples/eliza-agent`](examples/eliza-agent).

---

## 1. ElizaOS Integration (legacy PolicyGuard path)

Counters memory-poisoning attacks by injecting a security evaluator, protected transaction action, and security context provider:

```typescript
import { createGuardianPlugin } from "@guardianai/middleware";

const agent = new Agent({
  // ... agent config ...
  plugins: [
    createGuardianPlugin({
      relayerUrl: "https://your-guardian-relayer.com",
      policyGuardAddress: "0xa0ae75AaaB1c05D49fd5D15a0a95e0171aEDbB7d",
      chainId: 10143, // Monad Testnet
      failClosed: true,
    }),
  ],
});
```

### What It Does in ElizaOS:
* **`GUARDIAN_MEMORY_GUARD` Evaluator:** Scans message history and persistent agent memory for prompt injection attacks before actions execute.
* **`EXECUTE_PROTECTED_TRANSACTION` Action:** Validates target addresses and wraps transaction calldata with EIP-712 proofs.
* **`guardianSecurityProvider`:** Injects real-time security status, Soulbound Passport score, and policy limits into agent reasoning.

---

## 2. Viem Client Decorator

Wraps Viem `WalletClient` transactions seamlessly:

```typescript
import { createWalletClient, http } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { withGuardianSecurity } from "@guardianai/middleware";

const baseClient = createWalletClient({
  account: privateKeyToAccount("0x..."),
  chain: monadTestnet,
  transport: http("https://testnet-rpc.monad.xyz"),
});

// Decorate with Guardian Security
const secureClient = withGuardianSecurity(baseClient, {
  agentId: "agent-alpha-01",
  relayerUrl: "http://localhost:8546",
  policyGuardAddress: "0xa0ae75AaaB1c05D49fd5D15a0a95e0171aEDbB7d",
});

// Outgoing transaction is automatically verified and wrapped!
const hash = await secureClient.sendTransaction({
  to: "0xTargetContract...",
  data: "0x...",
  value: 1000000000000000000n, // Preserves native MON value!
});
```

---

## 3. Python SDK & LangChain Integration

For Python-based AI agents, use the native Python middleware in `sdk/python/guardian_middleware.py`:

```python
from guardianai.middleware import (
    GuardianMiddleware,
    GuardianLangChainCallback,
    GuardianToolWrapper,
    guardian_web3_middleware,
)

# 1. Initialize Middleware
guard = GuardianMiddleware(
    relayer_url="http://localhost:8546",
    policy_guard_address="0xa0ae75AaaB1c05D49fd5D15a0a95e0171aEDbB7d",
    chain_id=10143,
    fail_closed=True,
)

# 2. LangChain Callback
callback = GuardianLangChainCallback(guard, agent_id="langchain-agent-01")

# 3. Web3.py Middleware
w3.middleware_onion.inject(
    guardian_web3_middleware(guard, agent_id="langchain-agent-01"),
    layer=0,
)
```

---

## Monad Testnet Deployment Reference

* **Network:** Monad Testnet (Chain ID `10143`)
* **Policy Guard Address:** [`0xa0ae75AaaB1c05D49fd5D15a0a95e0171aEDbB7d`](https://testnet.monadscan.com/address/0xa0ae75AaaB1c05D49fd5D15a0a95e0171aEDbB7d)
* **Policy Guard Selector:** `0x3cb7461c` (`executeWithAttestation(address,bytes,SafetyAttestation,bytes)`)
* **Status:** Verified Live on Monad Testnet (Chain ID 10143)

---

## Running Unit Tests

```bash
# Run standalone TypeScript test suite
node test/run-tests.js
```

