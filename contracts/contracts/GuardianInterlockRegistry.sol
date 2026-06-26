// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable2Step.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/**
 * @title GuardianInterlockRegistry
 * @notice Stores cross-agent interlock proofs on-chain, enabling mutual verification
 *         of interaction history between autonomous AI agents.
 */
contract GuardianInterlockRegistry is Ownable2Step, Pausable, ReentrancyGuard {

    // ── Types ────────────────────────────────────────────────────────────

    struct InterlockProof {
        bytes32 agentA;      // keccak256(agentA_id)
        bytes32 agentB;      // keccak256(agentB_id)
        bytes32 proofHash;
        uint256 nonce;
        uint256 registeredAt;
    }

    // ── State ────────────────────────────────────────────────────────────

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

    // ── Errors ───────────────────────────────────────────────────────────

    error InterlockAlreadyExists(bytes32 interlockId);
    error InvalidAgentHash();
    error InvalidProofHash();
    error InterlockNotFound(bytes32 interlockId);

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

        interlockId = keccak256(abi.encodePacked(_agentA, _agentB, _proofHash, _nonce));
        if (registry[interlockId].registeredAt != 0) revert InterlockAlreadyExists(interlockId);

        registry[interlockId] = InterlockProof({
            agentA: _agentA,
            agentB: _agentB,
            proofHash: _proofHash,
            nonce: _nonce,
            registeredAt: block.timestamp
        });

        interlockIds.push(interlockId);

        emit InterlockRegistered(interlockId, _agentA, _agentB, _proofHash, _nonce);
    }

    // ── Read Functions ───────────────────────────────────────────────────

    /**
     * @notice Verify and return the proof hash for a registered interlock.
     * @param _interlockId The ID of the interlock
     * @return proofHash The stored proof hash
     */
    function verifyInterlock(bytes32 _interlockId) external view returns (bytes32 proofHash) {
        InterlockProof memory proof = registry[_interlockId];
        if (proof.registeredAt == 0) revert InterlockNotFound(_interlockId);
        return proof.proofHash;
    }

    /**
     * @notice Get details of a registered interlock proof.
     */
    function getInterlock(bytes32 _interlockId) external view returns (InterlockProof memory) {
        InterlockProof memory proof = registry[_interlockId];
        if (proof.registeredAt == 0) revert InterlockNotFound(_interlockId);
        return proof;
    }

    /**
     * @notice Get total number of registered interlocks.
     */
    function getInterlockCount() external view returns (uint256) {
        return interlockIds.length;
    }

    // ── Admin Functions ──────────────────────────────────────────────────

    function pause() external onlyOwner { _pause(); }
    function unpause() external onlyOwner { _unpause(); }
}
