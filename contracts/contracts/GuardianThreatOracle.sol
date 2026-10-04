// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable2Step.sol";
import "@openzeppelin/contracts/utils/introspection/IERC165.sol";

/// @notice Chainlink CRE receiver interface (KeystoneForwarder calls onReport).
interface IReceiver is IERC165 {
    function onReport(bytes calldata metadata, bytes calldata report) external;
}

/**
 * @title GuardianThreatOracle
 * @notice On-chain scam list and threat stats written by a Chainlink CRE workflow.
 *
 *         Every node of the Chainlink DON fetches GuardianAI's threat feed independently, the nodes
 *         reach consensus, and the DON-signed report is delivered through Chainlink's Forwarder.
 *         No GuardianAI hot key can write here: only the Forwarder can.
 *
 *         GuardianAgentWallets read isFlagged() before every call, so a destination flagged by the
 *         DON is refused by the chain even if every off-chain component were bypassed.
 *
 *         Report ABI: (uint64 asOf, uint256 blocked, uint256 intercepted, uint256 passed,
 *                      bytes32 feedDigest, address[] addrs, bool[] flagged)
 */
contract GuardianThreatOracle is IReceiver, Ownable2Step {
    uint256 public constant MAX_ADDRESSES_PER_REPORT = 100;

    address public forwarder;
    /// @notice Optional: only accept reports from this workflow owner (0 = any, required for simulation).
    address public expectedWorkflowOwner;

    uint64 public lastAsOf;
    uint64 public updatedAt;
    uint64 public reportCount;
    uint256 public blocked;
    uint256 public intercepted;
    uint256 public passed;
    bytes32 public feedDigest;

    mapping(address => bool) public isFlagged;
    uint256 public flaggedCount;

    event ThreatReportAccepted(uint64 indexed asOf, uint256 blocked, uint256 intercepted, uint256 passed, bytes32 feedDigest, uint256 changes);
    event AddressFlagUpdated(address indexed account, bool flagged);
    event ForwarderUpdated(address indexed previousForwarder, address indexed newForwarder);
    event ExpectedWorkflowOwnerUpdated(address indexed previousOwner, address indexed newOwner);

    error InvalidSender(address sender, address expected);
    error InvalidWorkflowOwner(address got, address expected);
    error StaleReport(uint64 asOf, uint64 lastAsOf);
    error LengthMismatch();
    error TooManyAddresses(uint256 count);
    error ZeroAddress();

    constructor(address forwarder_) Ownable(msg.sender) {
        if (forwarder_ == address(0)) revert ZeroAddress();
        forwarder = forwarder_;
        emit ForwarderUpdated(address(0), forwarder_);
    }

    function onReport(bytes calldata metadata, bytes calldata report) external override {
        if (msg.sender != forwarder) revert InvalidSender(msg.sender, forwarder);
        if (expectedWorkflowOwner != address(0)) {
            address wfOwner = _workflowOwner(metadata);
            if (wfOwner != expectedWorkflowOwner) revert InvalidWorkflowOwner(wfOwner, expectedWorkflowOwner);
        }

        (
            uint64 asOf,
            uint256 blocked_,
            uint256 intercepted_,
            uint256 passed_,
            bytes32 digest,
            address[] memory addrs,
            bool[] memory flags
        ) = abi.decode(report, (uint64, uint256, uint256, uint256, bytes32, address[], bool[]));

        // Replays of an older report must never undo a newer one.
        if (asOf <= lastAsOf) revert StaleReport(asOf, lastAsOf);
        if (addrs.length != flags.length) revert LengthMismatch();
        if (addrs.length > MAX_ADDRESSES_PER_REPORT) revert TooManyAddresses(addrs.length);

        lastAsOf = asOf;
        updatedAt = uint64(block.timestamp);
        reportCount += 1;
        blocked = blocked_;
        intercepted = intercepted_;
        passed = passed_;
        feedDigest = digest;

        uint256 changes;
        for (uint256 i = 0; i < addrs.length; i++) {
            address a = addrs[i];
            if (a == address(0) || isFlagged[a] == flags[i]) continue;
            isFlagged[a] = flags[i];
            if (flags[i]) flaggedCount += 1; else flaggedCount -= 1;
            changes += 1;
            emit AddressFlagUpdated(a, flags[i]);
        }
        emit ThreatReportAccepted(asOf, blocked_, intercepted_, passed_, digest, changes);
    }

    function setForwarder(address newForwarder) external onlyOwner {
        if (newForwarder == address(0)) revert ZeroAddress();
        emit ForwarderUpdated(forwarder, newForwarder);
        forwarder = newForwarder;
    }

    function setExpectedWorkflowOwner(address newOwner) external onlyOwner {
        emit ExpectedWorkflowOwnerUpdated(expectedWorkflowOwner, newOwner);
        expectedWorkflowOwner = newOwner;
    }

    /// @notice Blocked share of intercepted traffic, in basis points.
    function blockRateBps() external view returns (uint256) {
        return intercepted == 0 ? 0 : (blocked * 10_000) / intercepted;
    }

    function supportsInterface(bytes4 interfaceId) public pure override returns (bool) {
        return interfaceId == type(IReceiver).interfaceId || interfaceId == type(IERC165).interfaceId;
    }

    /// @dev CRE metadata layout: workflowId (32) | workflowName (10) | workflowOwner (20).
    function _workflowOwner(bytes calldata metadata) private pure returns (address o) {
        if (metadata.length < 62) return address(0);
        o = address(bytes20(metadata[42:62]));
    }
}
