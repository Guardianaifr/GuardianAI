// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable2Step.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title GuardianThreatFeedRegistry
 * @notice Immutable on-chain registry of known malicious addresses (e.g. exploiters,
 *         phishers, honeypots). Supports both EVM addresses and non-EVM string addresses.
 *
 * @dev    Access control: all write functions are restricted to onlyOwner, consistent
 *         with the other 4 GuardianAI on-chain contracts (CortexAnchor, InsuranceLedger,
 *         InterlockRegistry, RiskAttestation). The previous AccessControl / FEED_WRITER_ROLE
 *         pattern was removed because:
 *           1. The role was only ever granted to the deployer EOA (same as the Ownable owner).
 *           2. No production code, test, or deployment script ever granted it to a second address.
 *           3. transferOwnership() does not transfer AccessControl roles, so the deployer EOA
 *              retained unilateral write access even after ownership was transferred to the
 *              GuardianTimelock — a gap not covered by onchain_safety.py's owner() guard.
 *         If a genuine multi-writer use case arises, use a V2 deployment with an explicit design.
 */
contract GuardianThreatFeedRegistry is Ownable2Step, Pausable {

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

    constructor() Ownable(msg.sender) {}

    // ── Write Functions ──────────────────────────────────────────────────

    /**
     * @notice Add a malicious EVM address to the registry.
     */
    function addAddress(address _malicious, string calldata _reason)
        external
        onlyOwner
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
        onlyOwner
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
        onlyOwner
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
     * @notice Batch-add EVM addresses. All-or-nothing: if any address is
     *         invalid, the entire call reverts (atomic).
     * @param _addresses  Array of malicious EVM addresses.
     * @param _reasons    Array of reason strings (same length as _addresses).
     */
    function addAddressesBatch(
        address[] calldata _addresses,
        string[] calldata _reasons
    ) external onlyOwner whenNotPaused {
        require(_addresses.length == _reasons.length, "Length mismatch");
        require(_addresses.length <= 50, "Batch too large");

        for (uint256 i = 0; i < _addresses.length; i++) {
            address addr = _addresses[i];
            require(addr != address(0), "Invalid address");
            if (!evmRegistry[addr].isMalicious) {
                evmAddresses.push(addr);
            }
            evmRegistry[addr] = ThreatInfo({
                isMalicious: true,
                reason: _reasons[i],
                addedAt: block.timestamp
            });
            emit AddressAdded(addr, _reasons[i]);
        }
    }

    /**
     * @notice Batch-add non-EVM string addresses. All-or-nothing.
     * @param _addresses  Array of malicious string addresses.
     * @param _reasons    Array of reason strings (same length as _addresses).
     */
    function addStringAddressesBatch(
        string[] calldata _addresses,
        string[] calldata _reasons
    ) external onlyOwner whenNotPaused {
        require(_addresses.length == _reasons.length, "Length mismatch");
        require(_addresses.length <= 50, "Batch too large");

        for (uint256 i = 0; i < _addresses.length; i++) {
            require(bytes(_addresses[i]).length > 0, "Empty string address");
            if (!stringRegistry[_addresses[i]].isMalicious) {
                stringAddresses.push(_addresses[i]);
            }
            stringRegistry[_addresses[i]] = ThreatInfo({
                isMalicious: true,
                reason: _reasons[i],
                addedAt: block.timestamp
            });
            emit StringAddressAdded(_addresses[i], _reasons[i]);
        }
    }

    /**
     * @notice Remove a non-EVM string address from the registry.
     */
    function removeStringAddress(string calldata _malicious)
        external
        onlyOwner
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
}
