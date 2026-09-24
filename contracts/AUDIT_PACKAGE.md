# GuardianAI Smart Contracts - Audit Package

## 1. Scope

The following 13 production contracts are in scope for the audit (excluding `mocks/` and `interfaces/`):

1. `contracts/contracts/GuardianCircuitBreaker.sol`
2. `contracts/contracts/GuardianCortexAnchor.sol`
3. `contracts/contracts/GuardianInsuranceLedger.sol`
4. `contracts/contracts/GuardianInterlockRegistry.sol`
5. `contracts/contracts/GuardianPassportSBT.sol`
6. `contracts/contracts/GuardianPolicyGuard.sol`
7. `contracts/contracts/GuardianProtectedVault.sol`
8. `contracts/contracts/GuardianRiskAttestation.sol`
9. `contracts/contracts/GuardianThreatConsumer.sol`
10. `contracts/contracts/GuardianThreatFeedRegistry.sol`
11. `contracts/contracts/GuardianTimelock.sol`
12. `contracts/contracts/MaliciousToken.sol`
13. `contracts/contracts/erc8004/IdentityRegistryTestnet.sol`

*(Note: `MockDependencies.sol`, `mocks/*`, and `interfaces/*` are explicitly out of scope).*

## 2. Architecture Overview

GuardianAI provides verifiable security and compliance primitives for autonomous AI agents on EVM-compatible chains (specifically Monad). The architecture relies on multiple specialized registries and ledgers:
- **Cortex Anchor**: Stores cryptographic Merkle roots for batch AI events.
- **Interlock Registry**: On-chain mutual verification of agent-to-agent interactions.
- **Insurance Ledger**: Manages policies with an explicit 100k cap.
- **Passport SBT**: ERC-5192 compliant soulbound token indicating trust tiers.
- **Risk Attestation & Threat Feed**: Registers security scores, block-listed addresses, and CRE telemetry.
- **Policy Guard & Circuit Breaker**: Integrations (EIP-712 and direct modifiers) for DeFi protocols to safely interact with agents.
- **Timelock**: A centralized 24-hour delayed executor for all configuration changes.

## 3. Known Issues & Design Decisions

- **Unbounded Arrays / Array Caps**: `GuardianCortexAnchor` and `GuardianInsuranceLedger` use arrays that are hard-capped to `100,000` items to avoid unbounded state growth and gas limits.
- **O(1) Threat Registry Removal**: `GuardianThreatFeedRegistry` uses a swap-and-pop algorithm for gas-efficient `O(1)` deletion of malicious entries.
- **SBT Non-Transferability**: `GuardianPassportSBT` overrides ERC-721 `_update` to unconditionally revert on transfers between non-zero addresses (enforcing ERC-5192).
- **Testnet 8004 Registry**: `IdentityRegistryTestnet.sol` is a minimal stand-in specifically for Monad testnet rehearsal. Mainnet integrations MUST point to the canonical ERC-8004 CREATE2 address.
- **Reentrancy Protection**: Key external functions use OpenZeppelin's `nonReentrant` in tandem with the Checks-Effects-Interactions (CEI) pattern.

## 4. Access Control Matrix

All core contracts inherit from `Ownable2Step`. Ownership will be transferred to `GuardianTimelock`.

| Contract / Role | Privileged Capabilities |
| --- | --- |
| **Owner (`GuardianTimelock`)** | `pause()`, `unpause()`, configure parameters (e.g., thresholds, signers, forwarders), mint/revoke SBTs, issue/revoke insurance certificates, register interlocks/cortex roots, manage threat registries. |
| **`attestationSigner`** | (PolicyGuard) Can cryptographically sign off-chain EIP-712 safety attestations that execute on-chain. |
| **`forwarderAddress`** | (ThreatConsumer) Chainlink CRE forwarder that pushes verified telemetry. |
| **Timelock Proposer** | Proposes operations with a minimum 24-hour delay. |
| **Timelock Executor** | `address(0)` (anyone can execute *after* the delay expires). |

## 5. Deployment Info

- **Network**: Monad Testnet
- **Chain ID**: 10143
- **RPC URL**: `https://testnet-rpc.monad.xyz` (or fallback tenderly virtual testnet)

## 6. Dependencies

- **Solidity Version**: `^0.8.20` (Compiled with `0.8.24`)
- **EVM Target**: `cancun`
- **Libraries**:
  - `@openzeppelin/contracts` `^5.1.0`
  - `@nomicfoundation/hardhat-toolbox` `^5.0.0`
