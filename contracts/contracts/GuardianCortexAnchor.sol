// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable2Step.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/**
 * @title GuardianCortexAnchor
 * @notice Immutable on-chain record of Merkle tree roots from GuardianAI Cortex.
 *         Each root commits a batch of AI agent decision hashes, providing a
 *         tamper-proof audit trail anchored to an EVM chain.
 *
 * @dev    Uses OpenZeppelin Ownable2Step (safe ownership transfer),
 *         Pausable (emergency stop), and ReentrancyGuard (future-proof).
 *
 *         Only the contract owner (the Guardian deployer wallet) can commit roots.
 *         Verification is public — anyone can check if a leaf is in a committed batch.
 */
contract GuardianCortexAnchor is Ownable2Step, Pausable, ReentrancyGuard {

    // ── Types ────────────────────────────────────────────────────────────

    struct Commitment {
        bytes32  merkleRoot;
        uint256  eventCount;
        bytes32  agentHash;       // keccak256(agentId)
        uint256  periodStart;     // UNIX timestamp
        uint256  periodEnd;       // UNIX timestamp
        uint256  committedAt;     // block.timestamp at commit time
        uint256  blockNumber;     // block.number at commit time
    }

    // ── State ────────────────────────────────────────────────────────────

    /// @notice Maximum commitments per agent (prevents unbounded array growth)
    uint256 public constant MAX_COMMITMENTS_PER_AGENT = 100_000;

    /// @notice Global list of all commitments (append-only)
    Commitment[] public commitments;

    /// @notice agentHash => list of commitment indices
    mapping(bytes32 => uint256[]) public agentCommitments;

    /// @notice merkleRoot => commitment index (0 = not found, actual index + 1)
    mapping(bytes32 => uint256) public rootIndex;

    /// @notice Total number of events anchored across all agents
    uint256 public totalEventsAnchored;

    // ── Events ───────────────────────────────────────────────────────────

    event RootCommitted(
        bytes32 indexed merkleRoot,
        bytes32 indexed agentHash,
        uint256 eventCount,
        uint256 periodStart,
        uint256 periodEnd,
        uint256 commitmentIndex
    );

    // ── Errors ───────────────────────────────────────────────────────────

    error EmptyRoot();
    error ZeroEventCount();
    error InvalidPeriod();
    error RootAlreadyCommitted(bytes32 root);
    error AgentLimitReached(bytes32 agentHash, uint256 limit);

    // ── Constructor ──────────────────────────────────────────────────────

    constructor() Ownable(msg.sender) {}

    // ── Write Functions ──────────────────────────────────────────────────

    /**
     * @notice Commit a Merkle root representing a batch of Cortex events.
     * @param _merkleRoot   The SHA-256 Merkle root hash (as bytes32)
     * @param _eventCount   Number of events in this batch
     * @param _agentHash    keccak256 hash of the agent ID
     * @param _periodStart  UNIX timestamp of the first event in the batch
     * @param _periodEnd    UNIX timestamp of the last event in the batch
     */
    function commitRoot(
        bytes32 _merkleRoot,
        uint256 _eventCount,
        bytes32 _agentHash,
        uint256 _periodStart,
        uint256 _periodEnd
    ) external onlyOwner whenNotPaused nonReentrant {
        if (_merkleRoot == bytes32(0)) revert EmptyRoot();
        if (_eventCount == 0) revert ZeroEventCount();
        if (_periodEnd < _periodStart) revert InvalidPeriod();
        if (rootIndex[_merkleRoot] != 0) revert RootAlreadyCommitted(_merkleRoot);
        if (agentCommitments[_agentHash].length >= MAX_COMMITMENTS_PER_AGENT) {
            revert AgentLimitReached(_agentHash, MAX_COMMITMENTS_PER_AGENT);
        }

        uint256 idx = commitments.length;
        commitments.push(Commitment({
            merkleRoot:  _merkleRoot,
            eventCount:  _eventCount,
            agentHash:   _agentHash,
            periodStart: _periodStart,
            periodEnd:   _periodEnd,
            committedAt: block.timestamp,
            blockNumber: block.number
        }));

        rootIndex[_merkleRoot] = idx + 1;  // +1 so 0 means "not found"
        agentCommitments[_agentHash].push(idx);
        totalEventsAnchored += _eventCount;

        emit RootCommitted(
            _merkleRoot, _agentHash, _eventCount,
            _periodStart, _periodEnd, idx
        );
    }

    // ── Read Functions ───────────────────────────────────────────────────

    /**
     * @notice Check if a Merkle root has been committed.
     * @return exists True if the root was committed
     * @return commitment The commitment data (zeroed if not found)
     */
    function getCommitment(bytes32 _merkleRoot)
        external view returns (bool exists, Commitment memory commitment)
    {
        uint256 idx = rootIndex[_merkleRoot];
        if (idx == 0) return (false, commitment);
        return (true, commitments[idx - 1]);
    }

    /**
     * @notice Verify a SHA-256 Merkle inclusion proof on-chain.
     * @param _leaf  The leaf hash
     * @param _proof Array of sibling hashes from leaf to root
     * @param _root  The expected Merkle root
     * @return valid True if the proof checks out
     *
     * @dev Uses sha256 precompile (address 0x02) to match the Python
     *      Merkle tree implementation. Pairs are sorted before hashing
     *      to ensure deterministic ordering.
     */
    function verifyInclusion(
        bytes32 _leaf,
        bytes32[] calldata _proof,
        bytes32 _root
    ) external pure returns (bool valid) {
        bytes32 current = _leaf;
        for (uint256 i = 0; i < _proof.length; i++) {
            bytes32 sibling = _proof[i];
            // Sort pair for deterministic ordering (matches Python implementation)
            if (current > sibling) {
                current = sha256(abi.encodePacked(sibling, current));
            } else {
                current = sha256(abi.encodePacked(current, sibling));
            }
        }
        return current == _root;
    }

    /**
     * @notice Get the total number of commitments.
     */
    function getCommitmentCount() external view returns (uint256) {
        return commitments.length;
    }

    /**
     * @notice Get commitment indices for an agent.
     * @param _agentHash keccak256 hash of the agent ID
     * @return indices Array of commitment indices
     */
    function getAgentCommitments(bytes32 _agentHash)
        external view returns (uint256[] memory indices)
    {
        return agentCommitments[_agentHash];
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
