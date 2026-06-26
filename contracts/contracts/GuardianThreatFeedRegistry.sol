// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable2Step.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title GuardianThreatFeedRegistry
 * @notice Immutable on-chain registry of known malicious addresses (e.g. exploiters,
 *         phishers, honeypots). Supports both EVM addresses and non-EVM string addresses.
 */
contract GuardianThreatFeedRegistry is Ownable2Step, AccessControl, Pausable {

    bytes32 public constant FEED_WRITER_ROLE = keccak256("FEED_WRITER_ROLE");

    // ── State ────────────────────────────────────────────────────────────

    /// @notice Maps EVM address to (isMalicious, reason)
    struct ThreatInfo {
        bool isMalicious;
        string reason;
        uint256 addedAt;
    }

    mapping(address => ThreatInfo) public evmRegistry;
    address[] public evmAddresses;

    mapping(string => ThreatInfo) public stringRegistry;
    string[] public stringAddresses;

    // ── Events ───────────────────────────────────────────────────────────

    event AddressAdded(address indexed malicious, string reason);
    event AddressRemoved(address indexed malicious);
    event StringAddressAdded(string indexed malicious, string reason);
    event StringAddressRemoved(string indexed malicious);

    // ── Constructor ──────────────────────────────────────────────────────

    constructor() Ownable(msg.sender) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(FEED_WRITER_ROLE, msg.sender);
    }

    // ── Write Functions ──────────────────────────────────────────────────

    /**
     * @notice Add a malicious EVM address to the registry.
     */
    function addAddress(address _malicious, string calldata _reason)
        external
        onlyRole(FEED_WRITER_ROLE)
        whenNotPaused
    {
        require(_malicious != address(0), "Invalid address");
        if (!evmRegistry[_malicious].isMalicious) {
            evmAddresses.push(_malicious);
        }
        evmRegistry[_malicious] = ThreatInfo({
            isMalicious: true,
            reason: _reason,
            addedAt: block.timestamp
        });
        emit AddressAdded(_malicious, _reason);
    }

    /**
     * @notice Remove an EVM address from the registry.
     */
    function removeAddress(address _malicious)
        external
        onlyRole(FEED_WRITER_ROLE)
        whenNotPaused
    {
        require(evmRegistry[_malicious].isMalicious, "Address not in registry");
        evmRegistry[_malicious].isMalicious = false;
        evmRegistry[_malicious].reason = "";
        
        // Remove from list (swap and pop)
        for (uint256 i = 0; i < evmAddresses.length; i++) {
            if (evmAddresses[i] == _malicious) {
                evmAddresses[i] = evmAddresses[evmAddresses.length - 1];
                evmAddresses.pop();
                break;
            }
        }
        emit AddressRemoved(_malicious);
    }

    /**
     * @notice Add a malicious non-EVM string address (e.g. Solana, BTC) to the registry.
     */
    function addStringAddress(string calldata _malicious, string calldata _reason)
        external
        onlyRole(FEED_WRITER_ROLE)
        whenNotPaused
    {
        require(bytes(_malicious).length > 0, "Empty string address");
        if (!stringRegistry[_malicious].isMalicious) {
            stringAddresses.push(_malicious);
        }
        stringRegistry[_malicious] = ThreatInfo({
            isMalicious: true,
            reason: _reason,
            addedAt: block.timestamp
        });
        emit StringAddressAdded(_malicious, _reason);
    }

    /**
     * @notice Remove a non-EVM string address from the registry.
     */
    function removeStringAddress(string calldata _malicious)
        external
        onlyRole(FEED_WRITER_ROLE)
        whenNotPaused
    {
        require(stringRegistry[_malicious].isMalicious, "Address not in registry");
        stringRegistry[_malicious].isMalicious = false;
        stringRegistry[_malicious].reason = "";

        for (uint256 i = 0; i < stringAddresses.length; i++) {
            if (keccak256(abi.encodePacked(stringAddresses[i])) == keccak256(abi.encodePacked(_malicious))) {
                stringAddresses[i] = stringAddresses[stringAddresses.length - 1];
                stringAddresses.pop();
                break;
            }
        }
        emit StringAddressRemoved(_malicious);
    }

    // ── Read Functions ───────────────────────────────────────────────────

    /**
     * @notice Check if an EVM address is malicious.
     */
    function isMalicious(address _query) external view returns (bool, string memory) {
        ThreatInfo memory info = evmRegistry[_query];
        return (info.isMalicious, info.reason);
    }

    /**
     * @notice Check if a string address is malicious.
     */
    function isMaliciousString(string calldata _query) external view returns (bool, string memory) {
        ThreatInfo memory info = stringRegistry[_query];
        return (info.isMalicious, info.reason);
    }

    /**
     * @notice Get total count of EVM malicious addresses.
     */
    function evmAddressCount() external view returns (uint256) {
        return evmAddresses.length;
    }

    /**
     * @notice Get total count of non-EVM malicious addresses.
     */
    function stringAddressCount() external view returns (uint256) {
        return stringAddresses.length;
    }

    // ── Admin/Pausable Functions ─────────────────────────────────────────

    function pause() external onlyOwner { _pause(); }
    function unpause() external onlyOwner { _unpause(); }

    // Override required by Solidity for multiple inheritance
    function supportsInterface(bytes4 interfaceId)
        public
        view
        override(AccessControl)
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }
}
