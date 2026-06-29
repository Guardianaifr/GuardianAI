---
name: guardian-phase5-contracts
description: >-
  Adds MAX_CERTIFICATES = 100,000 constant to GuardianInsuranceLedger.sol,
  adds CertificateLimitReached custom error (Solidity ^0.8.4+),
  adds cap check as FIRST line in issueCertificate() function body,
  creates GuardianTimelock.sol inheriting OpenZeppelin TimelockController,
  sets MIN_DELAY = 24 hours in GuardianTimelock.sol,
  creates deploy_timelock.js deployment script (env var driven),
  creates transfer_ownership_to_timelock.js script (env var driven),
  adds full Hardhat test suite for timelock (deploy, delay, cancel),
  and adds certificate cap validation tests.
---

# Guardian Phase 5: Smart Contract Hardening

## Overview
This skill implements Phase 5 of the GuardianAI Security Audit Remediation. It covers certificate storage safety limits and TimelockController setup.

## Workflow

### 1. Certificate Cap implementation
- **Target File:** `contracts/contracts/GuardianInsuranceLedger.sol`
  - Add constant: `uint256 public constant MAX_CERTIFICATES = 100_000;`
  - Add custom error: `error CertificateLimitReached();`
  - Add cap check as first line of `issueCertificate()`:
    ```solidity
    if (certificateIds.length >= MAX_CERTIFICATES) {
        revert CertificateLimitReached();
    }
    ```

### 2. TimelockController Integration
- **Timelock Contract:** Create `contracts/contracts/GuardianTimelock.sol` inheriting from `@openzeppelin/contracts/governance/TimelockController.sol`. Enforce a constant `MIN_DELAY = 24 hours`.
- **Deployment Script:** Create `contracts/scripts/deploy_timelock.js` to deploy the timelock with custom proposer/executor addresses.
- **Ownership Transfer:** Create `contracts/scripts/transfer_ownership_to_timelock.js` to loop through all 6 Guardian contracts and transfer ownership to the deployed timelock contract address.

### 3. Unit Testing
- **Certificate Cap Verification:** Update `contracts/test/GuardianInsuranceLedger.test.ts` to assert that the `MAX_CERTIFICATES` constant is correctly set and `CertificateLimitReached` exists in ABI.
- **Timelock Verification:** Create `contracts/test/GuardianTimelock.test.ts` verifying delay enforcement, role assignments, and cancel actions.

## Acceptance Criteria
- `npx hardhat test` passes all tests with 0 failures.
- `MAX_CERTIFICATES` is confirmed in the ledger ABI.
- `MIN_DELAY` is verified to be 86400 seconds.

## Human Decisions Pending
- Timelock delay choice (24h vs. 48h).
- Proposer address configuration (multisig required in production).
- Renouncing the initial admin key after all 6 contract ownership transfers have been confirmed.
- Executor role policy (open vs. restricted).
