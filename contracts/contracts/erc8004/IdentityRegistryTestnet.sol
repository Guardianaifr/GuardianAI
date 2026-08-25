// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";

/**
 * @title IdentityRegistryTestnet
 * @notice GuardianAI TESTNET STAND-IN implementing the canonical ERC-8004
 *         Identity Registry interface subset used by the GuardianAI registrar:
 *           register(string) -> uint256          (mints to msg.sender, emits Transfer)
 *           setMetadata(uint256,string,bytes)     (owner-only writes)
 *           getMetadata(uint256,string) view      -> bytes
 *           ownerOf(uint256) view                 -> address
 *
 * @dev This is NOT the audited reference contract from
 *      github.com/erc-8004/erc-8004-contracts — it is an ABI-faithful minimal
 *      stand-in for testnet rehearsal only. The canonical CREATE2 deployment
 *      (0x8004A169FB4a3325136EB29fA0ceB6D2e539a432) is mainnet-only today and
 *      absent from Base/Ethereum Sepolia (verified on-chain 2026-08-23 via
 *      eth_getCode). Mainnet integrations MUST target the canonical address.
 */
contract IdentityRegistryTestnet is ERC721 {
    string public constant REGISTRATION_TYPE =
        "https://eips.ethereum.org/EIPS/eip-8004#registration-v1";

    uint256 private _nextId = 1;
    mapping(uint256 => string) private _agentURI;
    mapping(uint256 => mapping(string => bytes)) private _metadata;

    event MetadataSet(uint256 indexed agentId, string indexed key, bytes value);

    error AgentNotFound();

    constructor()
        ERC721(
            "GuardianAI Testnet IdentityRegistry (ERC-8004 interface)",
            "GAI-8004"
        )
    {}

    function register(string calldata agentURI_) external returns (uint256 id) {
        id = _nextId++;
        _safeMint(msg.sender, id);
        _agentURI[id] = agentURI_;
    }

    function setMetadata(
        uint256 agentId,
        string calldata key,
        bytes calldata value
    ) external {
        if (_ownerOf(agentId) == address(0)) revert AgentNotFound();
        require(_ownerOf(agentId) == msg.sender, "NotAgentOwner");
        _metadata[agentId][key] = value;
        emit MetadataSet(agentId, key, value);
    }

    function getMetadata(
        uint256 agentId,
        string calldata key
    ) external view returns (bytes memory) {
        return _metadata[agentId][key];
    }

    function getAgentUri(uint256 agentId) external view returns (string memory) {
        return _agentURI[agentId];
    }
}
