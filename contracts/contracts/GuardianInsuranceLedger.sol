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
    // NOTE: Growing array can lead to high gas costs. Pagination should be added if off-chain enumeration becomes a bottleneck.
    bytes32[] public certificateIds;

    uint256 public constant MAX_CERTIFICATES = 100_000;

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
    error CertificateLimitReached();
    /// @notice _riskLevel must be exactly "LOW", "MEDIUM", or "HIGH" (case-sensitive, uppercase).
    error InvalidRiskLevel(string riskLevel);
    /// @notice _certId parameter was zero bytes32 (IL-1: distinguished from a genuine lookup-miss).
    error InvalidCertId();

    // ── Constructor ──────────────────────────────────────────────────────

    constructor() Ownable(msg.sender) {}

    // ── Write Functions ──────────────────────────────────────────────────

    /**
     * @notice Issue a new insurance certificate for an agent.
     *
     * @dev    Check ordering (IL-2): structural input validation first, then
     *         business-logic checks (cap, duplicate). This ensures a caller
     *         cannot distinguish cap-reached from invalid-input via error type.
     */
    function issueCertificate(
        bytes32 _certId,
        bytes32 _agentHash,
        uint256 _periodStart,
        uint256 _periodEnd,
        bytes32 _certHash,
        string calldata _riskLevel
    ) external onlyOwner whenNotPaused nonReentrant {
        // ── 1. Structural input validation (fast, no state reads) ────────
        if (_certId == bytes32(0))   revert InvalidCertId();
        if (_agentHash == bytes32(0)) revert InvalidAgentHash();
        if (_certHash == bytes32(0)) revert InvalidCertHash();
        if (_periodEnd < _periodStart) revert InvalidPeriod();
        require(bytes(_riskLevel).length <= 32, "Risk level too long");
        if (!_validRiskLevel(_riskLevel)) revert InvalidRiskLevel(_riskLevel);

        // ── 2. Business-logic / state-dependent checks ───────────────────
        if (certificateIds.length >= MAX_CERTIFICATES) {
            revert CertificateLimitReached();
        }
        if (certificates[_certId].issuedAt != 0) revert CertificateAlreadyExists(_certId);

        certificates[_certId] = Certificate({
            agentHash:   _agentHash,
            periodStart: _periodStart,
            periodEnd:   _periodEnd,
            certHash:    _certHash,
            riskLevel:   _riskLevel,
            issuedAt:    block.timestamp,
            revoked:     false
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

    /**
     * @notice Paginated read of certificateIds for off-chain enumeration (IL-3).
     * @param offset Zero-based start index into the certificateIds array.
     * @param limit  Maximum number of IDs to return. Capped internally at 1000.
     * @return page  Slice of certificate IDs beginning at `offset`.
     *
     * @dev  The public certificateIds array auto-getter provides index-by-index
     *       access; this function returns a contiguous slice to avoid forcing
     *       off-chain clients to make O(n) individual calls as the registry grows.
     *       Gas cost is caller-borne (view function).
     */
    function getCertificateIdsPage(uint256 offset, uint256 limit)
        external
        view
        returns (bytes32[] memory page)
    {
        uint256 total = certificateIds.length;
        if (offset >= total) return page; // empty slice
        uint256 cap = limit > 1000 ? 1000 : limit;
        uint256 end = offset + cap;
        if (end > total) end = total;
        page = new bytes32[](end - offset);
        for (uint256 i = 0; i < page.length; i++) {
            page[i] = certificateIds[offset + i];
        }
    }

    // ── Admin Functions ──────────────────────────────────────────────────

    function pause() external onlyOwner { _pause(); }
    function unpause() external onlyOwner { _unpause(); }

    // ── Internal Helpers ─────────────────────────────────────────────────

    /**
     * @dev Returns true iff riskLevel is exactly "LOW", "MEDIUM", or "HIGH".
     *      Casing is uppercase to match the Python _assess_risk() output convention.
     */
    function _validRiskLevel(string calldata riskLevel) internal pure returns (bool) {
        bytes32 h = keccak256(bytes(riskLevel));
        return h == keccak256(bytes("LOW"))
            || h == keccak256(bytes("MEDIUM"))
            || h == keccak256(bytes("HIGH"));
    }
}
