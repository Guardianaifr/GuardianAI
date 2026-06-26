// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable2Step.sol";

/**
 * @title GuardianRiskAttestation
 * @notice Stores on-chain risk score attestations for audited smart contracts,
 *         providing verifiable security assessments that other DeFi protocols can query.
 */
contract GuardianRiskAttestation is Ownable2Step {

    // ── Types ────────────────────────────────────────────────────────────

    struct Attestation {
        uint16 score;           // e.g. 9500 for 95.00%, or 95 for 95
        string grade;           // e.g. "A", "B", "C"
        bytes32 signalsHash;    // keccak256 hash of the full signals JSON/metadata
        uint256 attestedAt;
        uint256 blockNumber;
    }

    // ── State ────────────────────────────────────────────────────────────

    /// @notice contractAddress => chain => Attestation
    mapping(address => mapping(string => Attestation)) public attestations;

    /// @notice Total number of unique contract addresses attested
    uint256 public totalAttestations;

    // ── Events ───────────────────────────────────────────────────────────

    event RiskAttested(
        address indexed contractAddress,
        string indexed chain,
        uint16 score,
        string grade,
        bytes32 signalsHash
    );

    // ── Errors ───────────────────────────────────────────────────────────

    error InvalidScore();
    error InvalidGrade();
    error AttestationNotFound();

    // ── Constructor ──────────────────────────────────────────────────────

    constructor() Ownable(msg.sender) {}

    // ── Write Functions ──────────────────────────────────────────────────

    /**
     * @notice Attest to a smart contract's risk score and security grade.
     * @param _contractAddress The contract being audited
     * @param _chain           The chain name (e.g., "ethereum", "monad")
     * @param _score           The risk score (0-10000 or 0-100)
     * @param _grade           The letter grade ("A" through "F")
     * @param _signalsHash     Hash of audit signals
     */
    function attest(
        address _contractAddress,
        string calldata _chain,
        uint16 _score,
        string calldata _grade,
        bytes32 _signalsHash
    ) external onlyOwner {
        require(_contractAddress != address(0), "Invalid contract address");
        require(bytes(_chain).length > 0, "Invalid chain string");
        if (_score > 10000) revert InvalidScore();
        if (bytes(_grade).length == 0) revert InvalidGrade();

        if (attestations[_contractAddress][_chain].attestedAt == 0) {
            totalAttestations++;
        }

        attestations[_contractAddress][_chain] = Attestation({
            score: _score,
            grade: _grade,
            signalsHash: _signalsHash,
            attestedAt: block.timestamp,
            blockNumber: block.number
        });

        emit RiskAttested(_contractAddress, _chain, _score, _grade, _signalsHash);
    }

    // ── Read Functions ───────────────────────────────────────────────────

    /**
     * @notice Get the latest attestation details for a contract on a specific chain.
     */
    function getAttestation(address _contractAddress, string calldata _chain)
        external
        view
        returns (Attestation memory)
    {
        Attestation memory att = attestations[_contractAddress][_chain];
        if (att.attestedAt == 0) revert AttestationNotFound();
        return att;
    }
}
