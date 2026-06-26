// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/access/Ownable2Step.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";

/**
 * @title GuardianPassportSBT
 * @notice Non-transferable Soulbound Token (SBT) representing an AI agent's
 *         trust passport in the GuardianAI ecosystem. Implements ERC-5192
 *         (Minimal Soulbound NFTs) on top of OpenZeppelin's ERC-721.
 *
 * @dev    Transfers are blocked by overriding _update(). The token can only
 *         be minted to a new address or burned (revoked). Uses Ownable2Step
 *         for safe ownership transfer and Pausable for emergency stops.
 *
 *         ERC-5192 compliance: emits Locked(tokenId) on mint, locked() returns true.
 */
contract GuardianPassportSBT is ERC721, Ownable2Step, Pausable {

    // ── Types ────────────────────────────────────────────────────────────

    enum Tier { UNVERIFIED, SILVER, GOLD, DIAMOND }

    struct Passport {
        bytes32   agentHash;      // keccak256(agentId)
        Tier      tier;
        uint256   trustScore;     // Scaled by 100 (e.g. 8550 = 85.50)
        uint256   issuedAt;
        uint256   updatedAt;
        bool      revoked;
        string    metadataURI;    // Off-chain metadata pointer
    }

    // ── State ────────────────────────────────────────────────────────────

    /// @notice tokenId => passport data
    mapping(uint256 => Passport) public passports;

    /// @notice agentHash => tokenId (0 = not minted)
    mapping(bytes32 => uint256) public agentToken;

    /// @notice Auto-incrementing token ID counter
    uint256 private _nextTokenId;

    /// @notice Total active (non-revoked) passports
    uint256 public activePassportCount;

    // ── Events ───────────────────────────────────────────────────────────

    /// @notice ERC-5192: Emitted when a token is locked (soulbound)
    event Locked(uint256 indexed tokenId);

    /// @notice Emitted when a passport's trust score is updated
    event ScoreUpdated(
        uint256 indexed tokenId,
        bytes32 indexed agentHash,
        uint256 newScore,
        Tier    newTier
    );

    /// @notice Emitted when a passport is revoked
    event PassportRevoked(
        uint256 indexed tokenId,
        bytes32 indexed agentHash,
        uint256 revokedAt
    );

    // ── Errors ───────────────────────────────────────────────────────────

    error SoulboundTransferBlocked();
    error AgentAlreadyHasPassport(bytes32 agentHash);
    error PassportNotFound(uint256 tokenId);
    error PassportAlreadyRevoked(uint256 tokenId);
    error InvalidScore();

    // ── Constructor ──────────────────────────────────────────────────────

    constructor()
        ERC721("GuardianAI Passport", "GAPASS")
        Ownable(msg.sender)
    {
        _nextTokenId = 1;  // Start from 1 (0 reserved for "not found")
    }

    // ── Soulbound Enforcement (ERC-5192) ─────────────────────────────────

    /**
     * @dev Override _update to block all transfers. Only mint (from=0) and
     *      burn (to=0) are allowed. This makes the token soulbound.
     */
    function _update(
        address to,
        uint256 tokenId,
        address auth
    ) internal override returns (address) {
        address from = _ownerOf(tokenId);

        // Allow mint (from == 0) and burn (to == 0), block transfers
        if (from != address(0) && to != address(0)) {
            revert SoulboundTransferBlocked();
        }

        return super._update(to, tokenId, auth);
    }

    /**
     * @notice ERC-5192: Returns true if the token is locked (always true for SBTs).
     * @param tokenId The token to check
     * @return True (all tokens are permanently locked)
     */
    function locked(uint256 tokenId) external view returns (bool) {
        _requireOwned(tokenId);  // Revert if token doesn't exist
        return true;
    }

    // ── Write Functions ──────────────────────────────────────────────────

    /**
     * @notice Mint a new passport SBT for an AI agent.
     * @param _to         Address to receive the SBT (agent's owner wallet)
     * @param _agentHash  keccak256 hash of the agent ID
     * @param _score      Initial trust score (scaled by 100, e.g. 5000 = 50.00)
     * @param _metadataURI Off-chain metadata URI
     * @return tokenId    The minted token ID
     */
    function mint(
        address _to,
        bytes32 _agentHash,
        uint256 _score,
        string calldata _metadataURI
    ) external onlyOwner whenNotPaused returns (uint256 tokenId) {
        if (agentToken[_agentHash] != 0) {
            revert AgentAlreadyHasPassport(_agentHash);
        }
        if (_score > 10000) revert InvalidScore();

        tokenId = _nextTokenId++;
        _safeMint(_to, tokenId);

        passports[tokenId] = Passport({
            agentHash:   _agentHash,
            tier:        _classifyTier(_score),
            trustScore:  _score,
            issuedAt:    block.timestamp,
            updatedAt:   block.timestamp,
            revoked:     false,
            metadataURI: _metadataURI
        });

        agentToken[_agentHash] = tokenId;
        activePassportCount++;

        emit Locked(tokenId);  // ERC-5192 compliance
    }

    /**
     * @notice Update the trust score and tier for an existing passport.
     * @param _tokenId  The passport token ID
     * @param _newScore New trust score (scaled by 100)
     */
    function updateScore(uint256 _tokenId, uint256 _newScore)
        external onlyOwner whenNotPaused
    {
        Passport storage p = passports[_tokenId];
        if (p.issuedAt == 0) revert PassportNotFound(_tokenId);
        if (p.revoked) revert PassportAlreadyRevoked(_tokenId);
        if (_newScore > 10000) revert InvalidScore();

        p.trustScore = _newScore;
        p.tier = _classifyTier(_newScore);
        p.updatedAt = block.timestamp;

        emit ScoreUpdated(_tokenId, p.agentHash, _newScore, p.tier);
    }

    /**
     * @notice Revoke (burn) a passport. The SBT is destroyed and the agent
     *         slot is freed for re-issuance.
     * @param _tokenId The passport token ID to revoke
     */
    function revoke(uint256 _tokenId) external onlyOwner {
        Passport storage p = passports[_tokenId];
        if (p.issuedAt == 0) revert PassportNotFound(_tokenId);
        if (p.revoked) revert PassportAlreadyRevoked(_tokenId);

        p.revoked = true;
        p.updatedAt = block.timestamp;
        activePassportCount--;

        // Free agent slot so a new passport can be minted
        delete agentToken[p.agentHash];

        // Burn the token
        _update(address(0), _tokenId, address(0));

        emit PassportRevoked(_tokenId, p.agentHash, block.timestamp);
    }

    // ── Read Functions ───────────────────────────────────────────────────

    /**
     * @notice Get full passport data for a token.
     */
    function getPassport(uint256 _tokenId)
        external view returns (Passport memory)
    {
        if (passports[_tokenId].issuedAt == 0) revert PassportNotFound(_tokenId);
        return passports[_tokenId];
    }

    /**
     * @notice Get the token ID for an agent (by agentHash).
     * @return tokenId 0 if no passport exists
     */
    function getAgentTokenId(bytes32 _agentHash)
        external view returns (uint256)
    {
        return agentToken[_agentHash];
    }

    /**
     * @notice ERC-165: Declare support for ERC-721, ERC-165, and ERC-5192.
     */
    function supportsInterface(bytes4 interfaceId)
        public view override returns (bool)
    {
        // ERC-5192 interface ID = 0xb45a3c0e
        return interfaceId == 0xb45a3c0e || super.supportsInterface(interfaceId);
    }

    // ── Admin Functions ──────────────────────────────────────────────────

    function pause() external onlyOwner { _pause(); }
    function unpause() external onlyOwner { _unpause(); }

    // ── Internal ─────────────────────────────────────────────────────────

    function _classifyTier(uint256 _score) internal pure returns (Tier) {
        if (_score >= 9000) return Tier.DIAMOND;
        if (_score >= 7000) return Tier.GOLD;
        if (_score >= 4000) return Tier.SILVER;
        return Tier.UNVERIFIED;
    }
}
