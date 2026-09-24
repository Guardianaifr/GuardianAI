// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable2Step.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/**
 * @title GuardianInterlockRegistry
 * @notice Stores cross-agent interlock proofs on-chain, enabling mutual verification
 *         of interaction history between autonomous AI agents.
 *
 * @dev    IR-2 fix: Added soft-revoke mechanism (revokeInterlock) so that a bad
 *         registration — e.g. one produced by a compromised owner key with fabricated
 *         agent/proof data — can be corrected without deleting the historical record.
 *
 *         Design rationale: Interlock proofs are intentionally append-only (the
 *         InterlockRegistered event is permanent on-chain, providing non-repudiation).
 *         However, permanence of the *event log* is distinct from permanence of
 *         *current validity* — the same distinction made by GuardianInsuranceLedger's
 *         revokeCertificate(). A revoked record remains inspectable via getInterlock()
 *         but verifyInterlock() reverts InterlockAlreadyRevoked, so downstream
 *         protocols querying proof validity get the correct answer.
 *
 *         revokeInterlock() is whenNotPaused: revocation during an active pause/
 *         incident-response window is dangerous — a compromised owner key could use
 *         revocation as a cover-up tool to erase evidence of fabricated interlocks
 *         before the pause can be lifted. Requiring the contract to be unpaused to
 *         revoke ensures the emergency-stop and the corrective-action paths remain
 *         independent. (This matches InsuranceLedger's revokeCertificate() precedent.)
 */
contract GuardianInterlockRegistry is Ownable2Step, Pausable, ReentrancyGuard {

    // ── Types ────────────────────────────────────────────────────────────

    struct InterlockProof {
        bytes32 agentA;       // keccak256(agentA_id)
        bytes32 agentB;       // keccak256(agentB_id)
        bytes32 proofHash;
        uint256 nonce;
        uint256 registeredAt;
        bool    revoked;      // true after revokeInterlock(); record preserved for history
    }

    // ── State ────────────────────────────────────────────────────────────

    /// @notice Maximum interlocks to prevent unbounded array growth (Audit M-3)
    uint256 public constant MAX_INTERLOCKS = 100_000;

    /// @notice Maps interlockId to its proof details
    mapping(bytes32 => InterlockProof) public registry;

    /// @notice List of all registered interlock IDs
    bytes32[] public interlockIds;

    // ── Events ───────────────────────────────────────────────────────────

    event InterlockRegistered(
        bytes32 indexed interlockId,
        bytes32 indexed agentA,
        bytes32 indexed agentB,
        bytes32 proofHash,
        uint256 nonce
    );

    /// @notice Emitted when an owner revokes a previously registered interlock.
    ///         The record is preserved in storage and inspectable via getInterlock();
    ///         only verifyInterlock() treats a revoked record as invalid.
    event InterlockRevoked(bytes32 indexed interlockId);

    // ── Errors ───────────────────────────────────────────────────────────

    error InterlockAlreadyExists(bytes32 interlockId);
    error InvalidAgentHash();
    error InvalidProofHash();
    error InterlockNotFound(bytes32 interlockId);
    /// @notice Thrown by verifyInterlock() and revokeInterlock() when the record
    ///         has already been revoked.
    error InterlockAlreadyRevoked(bytes32 interlockId);
    /// @notice Audit M-3: array cap reached
    error InterlockLimitReached();

    // ── Constructor ──────────────────────────────────────────────────────

    constructor() Ownable(msg.sender) {}

    // ── Write Functions ──────────────────────────────────────────────────

    /**
     * @notice Register a mutual interlock proof between two agents.
     * @param _agentA    keccak256 hash of agent A ID
     * @param _agentB    keccak256 hash of agent B ID
     * @param _proofHash Hash of the interlock interaction proof
     * @param _nonce     Nonce for uniqueness
     * @return interlockId The computed unique ID of this interlock
     */
    function registerInterlock(
        bytes32 _agentA,
        bytes32 _agentB,
        bytes32 _proofHash,
        uint256 _nonce
    ) external onlyOwner whenNotPaused nonReentrant returns (bytes32 interlockId) {
        if (_agentA == bytes32(0) || _agentB == bytes32(0)) revert InvalidAgentHash();
        if (_proofHash == bytes32(0)) revert InvalidProofHash();
        if (interlockIds.length >= MAX_INTERLOCKS) revert InterlockLimitReached();  // Audit M-3

        interlockId = keccak256(abi.encodePacked(_agentA, _agentB, _proofHash, _nonce));
        if (registry[interlockId].registeredAt != 0) revert InterlockAlreadyExists(interlockId);

        registry[interlockId] = InterlockProof({
            agentA:       _agentA,
            agentB:       _agentB,
            proofHash:    _proofHash,
            nonce:        _nonce,
            registeredAt: block.timestamp,
            revoked:      false
        });

        interlockIds.push(interlockId);

        emit InterlockRegistered(interlockId, _agentA, _agentB, _proofHash, _nonce);
    }

    // ── Write Functions (admin) ──────────────────────────────────────────

    /**
     * @notice Revoke a previously registered interlock proof.
     * @param _interlockId The ID of the interlock to revoke.
     *
     * @dev    The record is marked revoked in storage but NOT deleted.
     *         getInterlock() continues to return the full record including
     *         revoked = true, preserving the tamper-evident audit trail.
     *         verifyInterlock() reverts InterlockAlreadyRevoked for revoked records.
     *
     *         whenNotPaused: prevents a compromised owner key from using revocation
     *         as a cover-up tool during an active incident (see contract NatSpec).
     */
    function revokeInterlock(bytes32 _interlockId) external onlyOwner whenNotPaused {
        InterlockProof storage proof = registry[_interlockId];
        if (proof.registeredAt == 0) revert InterlockNotFound(_interlockId);
        if (proof.revoked) revert InterlockAlreadyRevoked(_interlockId);
        proof.revoked = true;
        emit InterlockRevoked(_interlockId);
    }

    // ── Read Functions ───────────────────────────────────────────────────

    /**
     * @notice Verify and return the proof hash for a registered, non-revoked interlock.
     * @param _interlockId The ID of the interlock.
     * @return proofHash   The stored proof hash.
     * @dev    Reverts InterlockAlreadyRevoked if the record has been revoked.
     *         Use getInterlock() to inspect revoked records.
     */
    function verifyInterlock(bytes32 _interlockId) external view returns (bytes32 proofHash) {
        InterlockProof memory proof = registry[_interlockId];
        if (proof.registeredAt == 0) revert InterlockNotFound(_interlockId);
        if (proof.revoked) revert InterlockAlreadyRevoked(_interlockId);
        return proof.proofHash;
    }

    /**
     * @notice Get details of a registered interlock proof.
     * @param _interlockId The ID of the interlock.
     * @return The interlock proof details.
     */
    function getInterlock(bytes32 _interlockId) external view returns (InterlockProof memory) {
        InterlockProof memory proof = registry[_interlockId];
        if (proof.registeredAt == 0) revert InterlockNotFound(_interlockId);
        return proof;
    }

    /**
     * @notice Get total number of registered interlocks.
     * @return The total number of interlocks.
     */
    function getInterlockCount() external view returns (uint256) {
        return interlockIds.length;
    }

    // ── Admin Functions ──────────────────────────────────────────────────

    /**
     * @notice Pause the contract (emergency stop). Only owner.
     */
    function pause() external onlyOwner { _pause(); }

    /**
     * @notice Unpause the contract. Only owner.
     */
    function unpause() external onlyOwner { _unpause(); }
}
