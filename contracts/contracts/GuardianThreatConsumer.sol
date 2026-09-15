// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title  GuardianThreatConsumer
 * @notice On-chain consumer contract for Chainlink CRE workflow reports.
 *         Receives verified threat telemetry from the GuardianAI Decentralized
 *         Threat Oracle and stores it as an immutable on-chain record.
 *
 * @dev    Enforces forwarder-based access control so that only the authorized
 *         Chainlink CRE Forwarder contract or contract owner can submit verified reports.
 *
 *         Architecture:
 *         ┌──────────────────┐     ┌──────────────┐     ┌─────────────────────┐
 *         │ CRE Workflow DON │────▶│  Forwarder   │────▶│ GuardianThreatCon-  │
 *         │ (consensus)      │     │  (Chainlink)  │     │ sumer (this)        │
 *         └──────────────────┘     └──────────────┘     └─────────────────────┘
 */
contract GuardianThreatConsumer {

    // ── Structs ─────────────────────────────────────────────────────────

    struct ThreatReport {
        uint256 blocked;        // Total blocked threats
        uint256 intercepted;    // Total intercepted requests
        uint256 passed;         // Total passed (clean) requests
        string  threatDigest;   // Merkle root or SHA-256 digest of threat data
        uint256 updatedAt;      // Block timestamp of this report
    }

    // ── Errors ──────────────────────────────────────────────────────────

    error UnauthorizedCaller(address caller);
    error ZeroAddress();

    // ── State ───────────────────────────────────────────────────────────

    address public owner;
    address public forwarderAddress;

    ThreatReport public latestReport;
    uint256 public reportCount;
    mapping(uint256 => ThreatReport) public reports;

    // ── Events ──────────────────────────────────────────────────────────

    event ThreatReportReceived(
        uint256 indexed reportId,
        uint256 blocked,
        uint256 intercepted,
        uint256 passed,
        string  threatDigest
    );

    event ForwarderUpdated(address indexed previousForwarder, address indexed newForwarder);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    // ── Modifiers ────────────────────────────────────────────────────────

    modifier onlyAuthorized() {
        if (msg.sender != forwarderAddress && msg.sender != owner) {
            revert UnauthorizedCaller(msg.sender);
        }
        _;
    }

    modifier onlyOwner() {
        if (msg.sender != owner) {
            revert UnauthorizedCaller(msg.sender);
        }
        _;
    }

    // ── Constructor ──────────────────────────────────────────────────────

    /**
     * @notice Initialize the consumer contract with optional forwarder address.
     * @param  _forwarderAddress Chainlink CRE Forwarder address on Monad (or address(0) to configure later).
     */
    constructor(address _forwarderAddress) {
        owner = msg.sender;
        forwarderAddress = _forwarderAddress;
        emit OwnershipTransferred(address(0), msg.sender);
        if (_forwarderAddress != address(0)) {
            emit ForwarderUpdated(address(0), _forwarderAddress);
        }
    }

    // ── Admin Functions ──────────────────────────────────────────────────

    /**
     * @notice Set or rotate the authorized CRE Forwarder contract address.
     * @param  _forwarderAddress Address of the new CRE Forwarder.
     */
    function setForwarderAddress(address _forwarderAddress) external onlyOwner {
        emit ForwarderUpdated(forwarderAddress, _forwarderAddress);
        forwarderAddress = _forwarderAddress;
    }

    /**
     * @notice Transfer ownership of the consumer contract.
     * @param  newOwner Address of the new owner.
     */
    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert ZeroAddress();
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    // ── Report Handler ──────────────────────────────────────────────────

    /**
     * @notice Called by the CRE Forwarder (or owner) to deliver a verified threat report.
     * @param  report ABI-encoded (uint256, uint256, uint256, string) payload
     *                containing blocked, intercepted, passed, and threatDigest.
     */
    function onReport(bytes calldata report) external onlyAuthorized {
        (
            uint256 blocked,
            uint256 intercepted,
            uint256 passed,
            string memory threatDigest
        ) = abi.decode(report, (uint256, uint256, uint256, string));

        reportCount++;

        ThreatReport memory r = ThreatReport({
            blocked:       blocked,
            intercepted:   intercepted,
            passed:        passed,
            threatDigest:  threatDigest,
            updatedAt:     block.timestamp
        });

        reports[reportCount] = r;
        latestReport = r;

        emit ThreatReportReceived(
            reportCount,
            blocked,
            intercepted,
            passed,
            threatDigest
        );
    }

    // ── View Functions ──────────────────────────────────────────────────

    /**
     * @notice Check if the system is actively detecting threats.
     * @return true if more than 0 threats have been blocked.
     */
    function isActivelyProtecting() external view returns (bool) {
        return latestReport.blocked > 0;
    }

    /**
     * @notice Calculate the block rate as a percentage (basis points).
     * @return Block rate in basis points (e.g., 500 = 5.00%).
     */
    function blockRateBps() external view returns (uint256) {
        uint256 total = latestReport.intercepted;
        if (total == 0) return 0;
        return (latestReport.blocked * 10_000) / total;
    }
}
