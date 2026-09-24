// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./interfaces/IGuardianRiskAttestation.sol";
import "./interfaces/IGuardianThreatFeed.sol";

/**
 * @title GuardianCircuitBreaker
 * @notice Abstract contract that DeFi protocols inherit for live Guardian protection.
 *         Provides modifiers that check risk attestations and threat feeds before
 *         allowing sensitive operations to execute.
 *
 * @dev    Usage: inherit this contract and apply `guardianProtected` to sensitive
 *         functions (withdraw, swap, mint, bridge). If Guardian has flagged the
 *         caller or the contract itself, the transaction reverts.
 *
 *         Two modifier variants:
 *         - guardianProtected:       fail-open if no attestation exists (gradual adoption)
 *         - guardianProtectedStrict: fail-closed if no attestation exists (high-value vaults)
 *
 *         Access control is self-contained via circuitBreakerAdmin — does not force
 *         inheriting contracts to use any specific Ownable pattern.
 *
 *         No TransactionBlocked events: emit before revert discards logs. Off-chain
 *         blocked-attempt monitoring comes from the RPC Relay's blocked_transactions
 *         table (Phase 1). Custom errors provide sufficient on-chain revert data.
 *
 *         Immutable registry addresses: a Guardian redeployment orphans inheriting
 *         contracts — deliberate, matches how other protocols handle oracle/registry upgrades.
 *
 * Example:
 *   contract MyVault is GuardianCircuitBreaker {
 *       constructor(address _attestation, address _threatFeed)
 *           GuardianCircuitBreaker(_attestation, _threatFeed, msg.sender) {}
 *
 *       function withdraw(uint256 amount) external guardianProtected {
 *           // Only executes if caller is not flagged & contract risk score is healthy
 *       }
 *   }
 */
abstract contract GuardianCircuitBreaker {

    // ── State ────────────────────────────────────────────────────────────

    IGuardianRiskAttestation public immutable riskAttestation;
    IGuardianThreatFeed     public immutable threatFeed;
    string  public chainName;                   // Audit M-1: parameterized chain name

    address public circuitBreakerAdmin;
    uint16  public riskScoreThreshold = 6000;   // Block if score < 60% (below grade D)
    bool    public circuitBreakerActive = true;

    // ── Events ───────────────────────────────────────────────────────────

    event CircuitBreakerToggled(bool active);
    event RiskThresholdUpdated(uint16 oldThreshold, uint16 newThreshold);
    event CircuitBreakerAdminTransferred(address indexed previousAdmin, address indexed newAdmin);

    // ── Errors ───────────────────────────────────────────────────────────

    error CallerFlaggedMalicious(address caller);
    error ContractRiskTooHigh(uint16 currentScore, uint16 threshold);
    error NotCircuitBreakerAdmin();
    error ZeroAddress();
    error InvalidThreshold();                   // Audit L-2: threshold bounds check

    // ── Modifiers ────────────────────────────────────────────────────────

    modifier onlyCircuitBreakerAdmin() {
        if (msg.sender != circuitBreakerAdmin) revert NotCircuitBreakerAdmin();
        _;
    }

    // ── Constructor ──────────────────────────────────────────────────────

    constructor(address _riskAttestation, address _threatFeed, address _admin, string memory _chainName) {
        if (_riskAttestation == address(0)) revert ZeroAddress();
        if (_threatFeed == address(0)) revert ZeroAddress();
        if (_admin == address(0)) revert ZeroAddress();
        require(bytes(_chainName).length > 0, "Empty chain name");
        riskAttestation     = IGuardianRiskAttestation(_riskAttestation);
        threatFeed          = IGuardianThreatFeed(_threatFeed);
        circuitBreakerAdmin = _admin;
        chainName           = _chainName;
    }

    // ── Core Modifiers ───────────────────────────────────────────────────

    /**
     * @notice Core modifier — fail-open for unaudited contracts.
     *         Apply to sensitive functions (withdraw, swap, mint, bridge).
     *         Checks: (1) caller not in threat feed, (2) contract risk score healthy.
     *         If no attestation exists, allows execution (gradual adoption).
     */
    modifier guardianProtected() {
        if (circuitBreakerActive) {
            // Check 1: Is the caller flagged as malicious?
            (bool isMalicious, ) = threatFeed.isMalicious(msg.sender);
            if (isMalicious) revert CallerFlaggedMalicious(msg.sender);

            // Check 2: Is this contract's risk score below threshold?
            try riskAttestation.getAttestation(address(this), chainName) returns (
                IGuardianRiskAttestation.Attestation memory att
            ) {
                if (att.score < riskScoreThreshold) {
                    revert ContractRiskTooHigh(att.score, riskScoreThreshold);
                }
            } catch {
                // No attestation exists — fail-open (allow execution)
            }
        }
        _;
    }

    /**
     * @notice Strict modifier — fail-closed for unaudited contracts.
     *         If no attestation exists, reverts (high-value vault protection).
     */
    modifier guardianProtectedStrict() {
        if (circuitBreakerActive) {
            (bool isMalicious, ) = threatFeed.isMalicious(msg.sender);
            if (isMalicious) revert CallerFlaggedMalicious(msg.sender);

            IGuardianRiskAttestation.Attestation memory att =
                riskAttestation.getAttestation(address(this), chainName);
            if (att.score < riskScoreThreshold) {
                revert ContractRiskTooHigh(att.score, riskScoreThreshold);
            }
        }
        _;
    }

    // ── Admin Functions (access-controlled) ──────────────────────────────

    /**
     * @notice Toggles the circuit breaker on or off.
     * @param _active True to enable the circuit breaker, false to disable.
     */
    function setCircuitBreakerActive(bool _active) external onlyCircuitBreakerAdmin {
        circuitBreakerActive = _active;
        emit CircuitBreakerToggled(_active);
    }

    /**
     * @notice Updates the risk score threshold required for execution.
     * @param _threshold The new risk score threshold (0-10000).
     */
    function setRiskScoreThreshold(uint16 _threshold) external onlyCircuitBreakerAdmin {
        if (_threshold > 10000) revert InvalidThreshold();   // Audit L-2: bounds check
        uint16 old = riskScoreThreshold;
        riskScoreThreshold = _threshold;
        emit RiskThresholdUpdated(old, _threshold);
    }

    /**
     * @notice Transfers the circuit breaker admin role to a new address.
     * @param _newAdmin The address of the new admin.
     */
    function transferCircuitBreakerAdmin(address _newAdmin) external onlyCircuitBreakerAdmin {
        if (_newAdmin == address(0)) revert ZeroAddress();
        address old = circuitBreakerAdmin;
        circuitBreakerAdmin = _newAdmin;
        emit CircuitBreakerAdminTransferred(old, _newAdmin);
    }
}
