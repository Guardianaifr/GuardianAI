// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable2Step.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/**
 * @title GuardianInsuranceLedger
 * @notice Anchors signed insurance certificates on-chain, storing integrity hashes
 *         and validity periods to verify the insurance status of AI agents.
 */
contract GuardianInsuranceLedger is Ownable2Step, Pausable, ReentrancyGuard {

    // ── Types ────────────────────────────────────────────────────────────

    struct Certificate {
        bytes32 agentHash;      // keccak256(agentId)
        uint256 periodStart;    // UNIX timestamp
        uint256 periodEnd;      // UNIX timestamp
        bytes32 certHash;       // Hash of the full certificate document
        string riskLevel;       // e.g. "LOW", "MEDIUM", "HIGH"
        uint256 issuedAt;
        bool revoked;
    }

    // ── State ────────────────────────────────────────────────────────────

    /// @notice Maps certificate ID (bytes32) to its data
    mapping(bytes32 => Certificate) public certificates;

    /// @notice List of all certificate IDs
    bytes32[] public certificateIds;

    // ── Events ───────────────────────────────────────────────────────────

    event CertificateIssued(
        bytes32 indexed certId,
        bytes32 indexed agentHash,
        uint256 periodStart,
        uint256 periodEnd,
        bytes32 certHash,
        string riskLevel
    );

    event CertificateRevoked(bytes32 indexed certId);

    // ── Errors ───────────────────────────────────────────────────────────

    error CertificateAlreadyExists(bytes32 certId);
    error CertificateNotFound(bytes32 certId);
    error InvalidAgentHash();
    error InvalidPeriod();
    error InvalidCertHash();
    error CertificateAlreadyRevoked(bytes32 certId);

    // ── Constructor ──────────────────────────────────────────────────────

    constructor() Ownable(msg.sender) {}

    // ── Write Functions ──────────────────────────────────────────────────

    /**
     * @notice Issue a new insurance certificate for an agent.
     */
    function issueCertificate(
        bytes32 _certId,
        bytes32 _agentHash,
        uint256 _periodStart,
        uint256 _periodEnd,
        bytes32 _certHash,
        string calldata _riskLevel
    ) external onlyOwner whenNotPaused nonReentrant {
        if (_certId == bytes32(0)) revert CertificateNotFound(_certId);
        if (_agentHash == bytes32(0)) revert InvalidAgentHash();
        if (_periodEnd < _periodStart) revert InvalidPeriod();
        if (_certHash == bytes32(0)) revert InvalidCertHash();
        if (certificates[_certId].issuedAt != 0) revert CertificateAlreadyExists(_certId);

        certificates[_certId] = Certificate({
            agentHash: _agentHash,
            periodStart: _periodStart,
            periodEnd: _periodEnd,
            certHash: _certHash,
            riskLevel: _riskLevel,
            issuedAt: block.timestamp,
            revoked: false
        });

        certificateIds.push(_certId);

        emit CertificateIssued(_certId, _agentHash, _periodStart, _periodEnd, _certHash, _riskLevel);
    }

    /**
     * @notice Revoke a certificate.
     */
    function revokeCertificate(bytes32 _certId) external onlyOwner whenNotPaused nonReentrant {
        Certificate storage cert = certificates[_certId];
        if (cert.issuedAt == 0) revert CertificateNotFound(_certId);
        if (cert.revoked) revert CertificateAlreadyRevoked(_certId);

        cert.revoked = true;

        emit CertificateRevoked(_certId);
    }

    // ── Read Functions ───────────────────────────────────────────────────

    /**
     * @notice Fetch certificate details.
     */
    function getCertificate(bytes32 _certId) external view returns (Certificate memory) {
        Certificate memory cert = certificates[_certId];
        if (cert.issuedAt == 0) revert CertificateNotFound(_certId);
        return cert;
    }

    /**
     * @notice Get total certificate count.
     */
    function getCertificateCount() external view returns (uint256) {
        return certificateIds.length;
    }

    // ── Admin Functions ──────────────────────────────────────────────────

    function pause() external onlyOwner { _pause(); }
    function unpause() external onlyOwner { _unpause(); }
}
