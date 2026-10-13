# GuardianAI Smart Contracts - Audit Package

Status (October 2026): deployed on Monad testnet (chain ID 10143), **not yet audited by a third party**.
Test suite: 271 Hardhat tests across 15 files in `contracts/test/` (`npx hardhat test`).

## 1. Scope

Production contracts in scope (excluding `mocks/` and `interfaces/`):

**Agent payment path (added October 2026)**
1. `contracts/contracts/GuardianAgentWallet.sol`: per-agent contract wallet; every call needs the operator key **and** a GuardianAI EIP-712 attestation bound to the wallet; checks the threat oracle.
2. `contracts/contracts/GuardianAgentWalletFactory.sol`: CREATE2 factory; the salt includes the caller so wallet addresses cannot be squatted.
3. `contracts/contracts/GuardianThreatOracle.sol`: Chainlink CRE receiver (`IReceiver` + ERC-165); only the configured Forwarder can write the scam list.
4. `contracts/contracts/GuardianPassportIssuer.sol`: owns the passport SBT; lets a factory wallet owner self-claim one lowest-tier Agent ID card.

**Original suite**
5. `contracts/contracts/GuardianPolicyGuard.sol`
6. `contracts/contracts/GuardianPassportSBT.sol`
7. `contracts/contracts/GuardianThreatFeedRegistry.sol`
8. `contracts/contracts/GuardianRiskAttestation.sol`
9. `contracts/contracts/GuardianCortexAnchor.sol`
10. `contracts/contracts/GuardianInterlockRegistry.sol`
11. `contracts/contracts/GuardianInsuranceLedger.sol`
12. `contracts/contracts/GuardianCircuitBreaker.sol`
13. `contracts/contracts/GuardianTimelock.sol`
14. `contracts/contracts/GuardianThreatConsumer.sol` (earlier stats-only CRE consumer, superseded by `GuardianThreatOracle`)
15. `contracts/contracts/erc8004/IdentityRegistryTestnet.sol`

**Reference / test only (not for production deployment)**
- `contracts/contracts/GuardianProtectedVault.sol`: example integration of `GuardianCircuitBreaker`.
- `contracts/contracts/MaliciousToken.sol`: adversarial test token.

*(`MockDependencies.sol`, `mocks/*` and `interfaces/*` are out of scope.)*

## 2. Architecture Overview

GuardianAI provides verifiable security primitives for autonomous AI agents on Monad:
- **Agent Wallet + Factory**: the agent's funds live in a contract, not in the agent's key. `execute` requires `msg.sender == operator` and a valid GuardianAI signature for the exact target, value and calldata hash, a nonce and a deadline, then checks the risk limit, the agent's passport and the threat oracle. The owner can `ownerExecute` as the recovery path.
- **Threat Oracle**: DON-signed reports (consensus over GuardianAI's feed) flag addresses; reports must be newer than the last one; optional workflow-owner pinning.
- **Passport Issuer + Passport SBT**: ERC-5192 soulbound Agent ID cards with trust tiers and permanent revocation tombstones.
- **Policy Guard & Circuit Breaker**: EIP-712 attestation gate with namespaced nonces, selector allowlists and outflow caps for the shared-spender path; modifiers for DeFi protocols.
- **Cortex Anchor**: Merkle roots for batched AI events.
- **Interlock Registry**: on-chain mutual verification of agent-to-agent interactions.
- **Insurance Ledger**: insurance certificate anchoring with a 100k cap.
- **Risk Attestation & Threat Feed Registry**: security scores and block-listed addresses.
- **Timelock**: 24-hour delayed executor intended to own the suite.

## 3. Known Issues & Design Decisions

- **Owner override**: `GuardianAgentWallet.ownerExecute` bypasses GuardianAI by design. In production the owner should be a passkey, multisig or the timelock.
- **Single attestation signer**: one hot key signs all approvals (rotated away from the deployer key; `tools/rotate_attestation_signer.py`). KMS/HSM or threshold signing is planned.
- **Shared-spender pulls (PolicyGuard path)**: `transferFrom` pulls need an owner-signed EIP-712 authorization checked by the relay; new agents should use `GuardianAgentWallet`, which has no shared spender.
- **Unbounded Arrays / Array Caps**: `GuardianCortexAnchor` and `GuardianInsuranceLedger` cap arrays at `100,000` items.
- **O(1) Threat Registry Removal**: `GuardianThreatFeedRegistry` uses swap-and-pop deletion.
- **SBT Non-Transferability**: `GuardianPassportSBT` overrides ERC-721 `_update` to revert on transfers between non-zero addresses (ERC-5192).
- **Testnet 8004 Registry**: `IdentityRegistryTestnet.sol` is a minimal stand-in for Monad testnet rehearsal. Mainnet integrations MUST point to the canonical ERC-8004 CREATE2 address.
- **Reentrancy Protection**: Key external functions use OpenZeppelin's `nonReentrant` with Checks-Effects-Interactions.

## 4. Access Control Matrix

Core contracts inherit from `Ownable2Step`. Ownership is intended to move to `GuardianTimelock` (`scripts/transfer_ownership_to_timelock.js`); **on testnet the deployed suite is still owned by the deployer EOA.**

| Contract / Role | Privileged Capabilities |
| --- | --- |
| **Owner (deployer today, `GuardianTimelock` later)** | `pause()`, `unpause()`, configure parameters (thresholds, signers, forwarders), mint/revoke SBTs (through `GuardianPassportIssuer`), issue/revoke insurance certificates, register interlocks/cortex roots, manage threat registries. |
| **Wallet owner** (`GuardianAgentWallet`) | Set operator, GuardianAI signer, passport registry, risk limit and threat oracle; pause/unpause; cancel nonces; `ownerExecute` (recovery). |
| **Wallet operator** (agent key) | `execute` with a valid GuardianAI attestation; pause (not unpause); cancel nonces. |
| **`attestationSigner`** | Signs EIP-712 safety attestations accepted by PolicyGuard and agent wallets. |
| **Chainlink Forwarder** | Only writer of `GuardianThreatOracle` (and, earlier, `GuardianThreatConsumer`). |
| **Timelock Proposer** | Proposes operations with a minimum 24-hour delay. |
| **Timelock Executor** | `address(0)` (anyone can execute *after* the delay expires). |

## 5. Deployment Info

- **Network**: Monad Testnet, chain ID 10143
- **RPC URL**: `https://testnet-rpc.monad.xyz` (or a Tenderly virtual testnet)
- **Addresses**: repository [README](../README.md#-verified-monad-testnet-deployments-chain-id-10143) and `deployments/monad_testnet_10143/`
- **Agent wallet deploy**: `scripts/deploy-agent-wallet.ts`; passport issuer: `scripts/deploy-passport-issuer.ts`

## 6. Dependencies

- **Solidity Version**: `^0.8.20` (compiled with `0.8.24`)
- **EVM Target**: `cancun`
- **Libraries**:
  - `@openzeppelin/contracts` `^5.1.0`
  - `@nomicfoundation/hardhat-toolbox` `^5.0.0`
- **Static analysis**: `slither.config.json`
