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
4. **Wraps Approved Transactions:** Re-routes transactions through [`GuardianPolicyGuard`](https://testnet.monadscan.com/address/0x90Fdc8E1e5C951701eCd84677038B38560CdEF60) (`0x90Fd...EF60`) on Monad Testnet (`0x3cb7461c`).
5. **Strictly Fails Closed:** If an attestation is rejected or the relayer is unreachable, execution halts immediately with `GuardianSecurityError`—un-attested transactions never reach the blockchain.

---

## 1. ElizaOS Integration (ai16z)

Counters memory-poisoning attacks by injecting a security evaluator, protected transaction action, and security context provider:

```typescript
import { createGuardianPlugin } from "@guardianai/middleware";

const agent = new Agent({
  // ... agent config ...
  plugins: [
    createGuardianPlugin({
      relayerUrl: "https://your-guardian-relayer.com",
      policyGuardAddress: "0x90Fdc8E1e5C951701eCd84677038B38560CdEF60",
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
  relayerUrl: "http://localhost:8000",
  policyGuardAddress: "0x90Fdc8E1e5C951701eCd84677038B38560CdEF60",
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
    relayer_url="http://localhost:8000",
    policy_guard_address="0x90Fdc8E1e5C951701eCd84677038B38560CdEF60",
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
* **Policy Guard Address:** [`0x90Fdc8E1e5C951701eCd84677038B38560CdEF60`](https://testnet.monadscan.com/address/0x90Fdc8E1e5C951701eCd84677038B38560CdEF60)
* **Policy Guard Selector:** `0x3cb7461c` (`executeWithAttestation(address,bytes,SafetyAttestation,bytes)`)
* **Status:** Verified Live on Monad Testnet (Chain ID 10143)

---

## Running Unit Tests

```bash
# Run standalone TypeScript test suite
node test/run-tests.js
```

