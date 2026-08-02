// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable2Step.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title GuardianThreatFeedRegistry
 * @notice On-chain registry of known malicious addresses (EVM and non-EVM).
 *
 * @dev    Access control: all write functions restricted to onlyOwner, consistent
 *         with the other 4 GuardianAI on-chain contracts. The previous AccessControl /
 *         FEED_WRITER_ROLE pattern was removed (TF-1): the role was only ever granted
 *         to the deployer EOA, and transferOwnership() does not transfer AccessControl
 *         roles — leaving the deployer with unilateral write access after ownership
 *         transfer to the GuardianTimelock.
 *
 *         Removal algorithm (TF-2/TF-3): evmAddresses and stringAddresses are bounded
 *         by MAX_EVM_REGISTRY_SIZE and MAX_STRING_REGISTRY_SIZE respectively.  Removal
 *         is O(1) via index mappings (evmIndex / stringIndex) rather than the previous
 *         O(n) linear scan.  On remove, the target slot is filled by swapping in the
 *         last element, the swapped element's index entry is updated, and the removed
 *         element's index entry is deleted.
 */
contract GuardianThreatFeedRegistry is Ownable2Step, Pausable {

    // ── Constants ────────────────────────────────────────────────────────

    uint256 public constant MAX_EVM_REGISTRY_SIZE    = 10_000;
    uint256 public constant MAX_STRING_REGISTRY_SIZE =  5_000;

    // ── Custom errors ────────────────────────────────────────────────────

    error EvmRegistryFull();
    error StringRegistryFull();

    // ── State ────────────────────────────────────────────────────────────

    struct ThreatInfo {
        bool    isMalicious;
        string  reason;
        uint256 addedAt;
    }

    // EVM address registry
    mapping(address => ThreatInfo) public evmRegistry;
    address[] public evmAddresses;
    /// @dev 0-based position of each address in evmAddresses[].
    ///      Only valid when evmRegistry[addr].isMalicious == true.
    mapping(address => uint256) private evmIndex;

    // String address registry (Solana, BTC, etc.)
    mapping(string => ThreatInfo) public stringRegistry;
    string[] public stringAddresses;
    /// @dev 0-based position of each string address, keyed by keccak256(abi.encodePacked(addr)).
    ///      Only valid when stringRegistry[addr].isMalicious == true.
    mapping(bytes32 => uint256) private stringIndex;

    // ── Events ───────────────────────────────────────────────────────────

    event AddressAdded(address indexed malicious, string reason);
    event AddressRemoved(address indexed malicious);
    event StringAddressAdded(string indexed malicious, string reason);
    event StringAddressRemoved(string indexed malicious);

    // ── Constructor ──────────────────────────────────────────────────────

    constructor() Ownable(msg.sender) {}

    // ── EVM write functions ──────────────────────────────────────────────

    /**
     * @notice Add a malicious EVM address to the registry.
     * @dev    Reverts with EvmRegistryFull if the registry has reached MAX_EVM_REGISTRY_SIZE.
     *         Re-adding an already-registered address only updates its reason/timestamp (no
     *         double-push to the array and no cap check).
     */
    function addAddress(address _malicious, string calldata _reason)
        external
        onlyOwner
        whenNotPaused
    {
        require(_malicious != address(0), "Invalid address");
        if (!evmRegistry[_malicious].isMalicious) {
            if (evmAddresses.length >= MAX_EVM_REGISTRY_SIZE) revert EvmRegistryFull();
            evmIndex[_malicious] = evmAddresses.length;
            evmAddresses.push(_malicious);
        }
        evmRegistry[_malicious] = ThreatInfo({
            isMalicious: true,
            reason:      _reason,
            addedAt:     block.timestamp
        });
        emit AddressAdded(_malicious, _reason);
    }

    /**
     * @notice Remove an EVM address from the registry. O(1) via index mapping.
     * @dev    Fills the vacated slot by swapping in the last element, updates that
     *         element's index entry, then pops.  Handles the single-element and
     *         last-element edge cases (idx == lastIdx) without a swap.
     */
    function removeAddress(address _malicious)
        external
        onlyOwner
        whenNotPaused
    {
        require(evmRegistry[_malicious].isMalicious, "Address not in registry");

        // CEI: state writes before any potential callbacks
        evmRegistry[_malicious].isMalicious = false;
        evmRegistry[_malicious].reason = "";

        uint256 idx     = evmIndex[_malicious];
        uint256 lastIdx = evmAddresses.length - 1;

        if (idx != lastIdx) {
            // Swap last element into the vacated slot
            address last = evmAddresses[lastIdx];
            evmAddresses[idx] = last;
            evmIndex[last] = idx;   // update the moved element's index
        }
        evmAddresses.pop();
        delete evmIndex[_malicious];

        emit AddressRemoved(_malicious);
    }

    /**
     * @notice Batch-add EVM addresses. All-or-nothing.
     * @dev    Reverts with EvmRegistryFull if any new entry would exceed the cap.
     *         Addresses already in the registry are updated in place (no cap check
     *         for them, no re-push).
     */
    function addAddressesBatch(
        address[] calldata _addresses,
        string[]  calldata _reasons
    ) external onlyOwner whenNotPaused {
        require(_addresses.length == _reasons.length, "Length mismatch");
        require(_addresses.length <= 50, "Batch too large");

        for (uint256 i = 0; i < _addresses.length; i++) {
            address addr = _addresses[i];
            require(addr != address(0), "Invalid address");
            if (!evmRegistry[addr].isMalicious) {
                if (evmAddresses.length >= MAX_EVM_REGISTRY_SIZE) revert EvmRegistryFull();
                evmIndex[addr] = evmAddresses.length;
                evmAddresses.push(addr);
            }
            evmRegistry[addr] = ThreatInfo({
                isMalicious: true,
                reason:      _reasons[i],
                addedAt:     block.timestamp
            });
            emit AddressAdded(addr, _reasons[i]);
        }
    }

    // ── String-address write functions ───────────────────────────────────

    /**
     * @notice Add a malicious non-EVM string address (e.g. Solana, BTC) to the registry.
     * @dev    Reverts with StringRegistryFull if the registry has reached MAX_STRING_REGISTRY_SIZE.
     */
    function addStringAddress(string calldata _malicious, string calldata _reason)
        external
        onlyOwner
        whenNotPaused
    {
        require(bytes(_malicious).length > 0, "Empty string address");
        if (!stringRegistry[_malicious].isMalicious) {
            if (stringAddresses.length >= MAX_STRING_REGISTRY_SIZE) revert StringRegistryFull();
            bytes32 key = keccak256(abi.encodePacked(_malicious));
            stringIndex[key] = stringAddresses.length;
            stringAddresses.push(_malicious);
        }
        stringRegistry[_malicious] = ThreatInfo({
            isMalicious: true,
            reason:      _reason,
            addedAt:     block.timestamp
        });
        emit StringAddressAdded(_malicious, _reason);
    }

    /**
     * @notice Remove a non-EVM string address from the registry. O(1) via index mapping.
     */
    function removeStringAddress(string calldata _malicious)
        external
        onlyOwner
        whenNotPaused
    {
        require(stringRegistry[_malicious].isMalicious, "Address not in registry");

        // CEI: state writes first
        stringRegistry[_malicious].isMalicious = false;
        stringRegistry[_malicious].reason = "";

        bytes32 key     = keccak256(abi.encodePacked(_malicious));
        uint256 idx     = stringIndex[key];
        uint256 lastIdx = stringAddresses.length - 1;

        if (idx != lastIdx) {
            string memory last = stringAddresses[lastIdx];
            stringAddresses[idx] = last;
            stringIndex[keccak256(abi.encodePacked(last))] = idx;
        }
        stringAddresses.pop();
        delete stringIndex[key];

        emit StringAddressRemoved(_malicious);
    }

    /**
     * @notice Batch-add non-EVM string addresses. All-or-nothing.
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
                if (stringAddresses.length >= MAX_STRING_REGISTRY_SIZE) revert StringRegistryFull();
                bytes32 key = keccak256(abi.encodePacked(_addresses[i]));
                stringIndex[key] = stringAddresses.length;
                stringAddresses.push(_addresses[i]);
            }
            stringRegistry[_addresses[i]] = ThreatInfo({
                isMalicious: true,
                reason:      _reasons[i],
                addedAt:     block.timestamp
            });
            emit StringAddressAdded(_addresses[i], _reasons[i]);
        }
    }

    // ── Read functions ───────────────────────────────────────────────────

    function isMalicious(address _query) external view returns (bool, string memory) {
        ThreatInfo memory info = evmRegistry[_query];
        return (info.isMalicious, info.reason);
    }

    function isMaliciousString(string calldata _query) external view returns (bool, string memory) {
        ThreatInfo memory info = stringRegistry[_query];
        return (info.isMalicious, info.reason);
    }

    function evmAddressCount() external view returns (uint256) {
        return evmAddresses.length;
    }

    function stringAddressCount() external view returns (uint256) {
        return stringAddresses.length;
    }

    // ── Admin/Pausable functions ─────────────────────────────────────────

    function pause()   external onlyOwner { _pause(); }
    function unpause() external onlyOwner { _unpause(); }
}
