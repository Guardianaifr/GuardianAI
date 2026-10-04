// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./GuardianAgentWallet.sol";

/**
 * @title GuardianAgentWalletFactory
 * @notice Deploys GuardianAgentWallets at deterministic (CREATE2) addresses. The caller becomes the
 *         wallet's owner, and the salt includes the caller, so nobody can squat another owner's address.
 *         Indexers (Envio) discover every wallet from the WalletCreated event.
 */
contract GuardianAgentWalletFactory {
    address public immutable guardianSigner;
    address public immutable passportRegistry;

    /// @notice owner => agentId => wallet
    mapping(address => mapping(bytes32 => address)) public walletOf;

    event WalletCreated(bytes32 indexed agentId, address indexed wallet, address indexed owner, address operator);

    error WalletExists(address wallet);
    error ZeroAddress();

    constructor(address guardianSigner_, address passportRegistry_) {
        if (guardianSigner_ == address(0)) revert ZeroAddress();
        guardianSigner = guardianSigner_;
        passportRegistry = passportRegistry_;
    }

    function createWallet(address operator, bytes32 agentId) external returns (address wallet) {
        address existing = walletOf[msg.sender][agentId];
        if (existing != address(0)) revert WalletExists(existing);
        wallet = address(new GuardianAgentWallet{salt: _salt(msg.sender, agentId)}(
            msg.sender, operator, guardianSigner, agentId, passportRegistry
        ));
        walletOf[msg.sender][agentId] = wallet;
        emit WalletCreated(agentId, wallet, msg.sender, operator);
    }

    function predictAddress(address owner, address operator, bytes32 agentId) external view returns (address) {
        bytes32 initHash = keccak256(abi.encodePacked(
            type(GuardianAgentWallet).creationCode,
            abi.encode(owner, operator, guardianSigner, agentId, passportRegistry)
        ));
        return address(uint160(uint256(keccak256(abi.encodePacked(
            bytes1(0xff), address(this), _salt(owner, agentId), initHash
        )))));
    }

    function _salt(address owner, bytes32 agentId) private pure returns (bytes32) {
        return keccak256(abi.encode(owner, agentId));
    }
}
