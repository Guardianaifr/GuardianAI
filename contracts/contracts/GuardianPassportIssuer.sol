// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable2Step.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

interface IGuardianPassportSBTAdmin {
    function mint(address to, bytes32 agentHash, uint256 score, string calldata metadataURI) external returns (uint256);
    function updateScore(uint256 tokenId, uint256 newScore) external;
    function revoke(uint256 tokenId) external;
    function pause() external;
    function unpause() external;
    function transferOwnership(address newOwner) external;
    function acceptOwnership() external;
}

interface IGuardianAgentWalletFactoryView {
    function walletOf(address owner, bytes32 agentId) external view returns (address);
}

/**
 * @title GuardianPassportIssuer
 * @notice Owner of GuardianPassportSBT. Lets anyone who owns a GuardianAgentWallet (created through the
 *         GuardianAI factory) claim ONE Agent ID card for that agent, at the lowest trust tier, by signing
 *         the claim themselves. No private key on a server can mint.
 *
 *         Everything else the SBT owner could do (mint any tier, re-score, revoke, pause, hand the SBT to a
 *         new owner) stays with this contract's owner (the GuardianAI deployer, later a timelock).
 *
 * @dev    Setup (Ownable2Step on the SBT): deployer calls passport.transferOwnership(issuer), then
 *         issuer.acceptPassportOwnership(). Undo: issuer.transferPassportOwnership(x), then x accepts.
 */
contract GuardianPassportIssuer is Ownable2Step, ReentrancyGuard {
    /// @notice Trust score for self-serve cards: 10.00, which the SBT classifies as UNVERIFIED.
    uint256 public constant SELF_SERVE_SCORE = 1000;

    IGuardianPassportSBTAdmin public immutable passport;
    IGuardianAgentWalletFactoryView public immutable factory;

    bool public claimsOpen = true;
    /// @notice Maximum number of self-serve cards (0 = no cap).
    uint256 public claimCap;
    uint256 public claimCount;
    /// @notice Owner address => token id of the card it claimed (0 = none). One self-serve card per address.
    mapping(address => uint256) public claimedTokenOf;

    event Claimed(address indexed owner, bytes32 indexed agentId, address indexed wallet, uint256 tokenId);
    event ClaimsConfigured(bool open, uint256 cap);

    error ZeroAddress();
    error ClaimsClosed();
    error ClaimCapReached(uint256 cap);
    error AlreadyClaimed(uint256 tokenId);
    error NoGuardedWallet(address owner, bytes32 agentId);

    constructor(address passport_, address factory_, address owner_) Ownable(owner_) {
        if (passport_ == address(0) || factory_ == address(0)) revert ZeroAddress();
        passport = IGuardianPassportSBTAdmin(passport_);
        factory = IGuardianAgentWalletFactoryView(factory_);
    }

    // ── Self-serve ────────────────────────────────────────────────────────

    /**
     * @notice Claim the lowest-tier Agent ID card for an agent whose GuardianAgentWallet you own.
     * @param agentId keccak256 of the agent_id string, exactly as passed to the factory's createWallet.
     */
    function claim(bytes32 agentId) external nonReentrant returns (uint256 tokenId) {
        if (!claimsOpen) revert ClaimsClosed();
        if (claimCap != 0 && claimCount >= claimCap) revert ClaimCapReached(claimCap);
        if (claimedTokenOf[msg.sender] != 0) revert AlreadyClaimed(claimedTokenOf[msg.sender]);
        address wallet = factory.walletOf(msg.sender, agentId);
        if (wallet == address(0)) revert NoGuardedWallet(msg.sender, agentId);

        claimCount++;
        // The SBT reverts if this agent already has a card or was permanently revoked.
        tokenId = passport.mint(msg.sender, agentId, SELF_SERVE_SCORE, "");
        claimedTokenOf[msg.sender] = tokenId;
        emit Claimed(msg.sender, agentId, wallet, tokenId);
    }

    // ── Admin (owner) ─────────────────────────────────────────────────────

    function setClaims(bool open, uint256 cap) external onlyOwner {
        claimsOpen = open;
        claimCap = cap;
        emit ClaimsConfigured(open, cap);
    }

    /// @notice Issue a card at any score (e.g. for GuardianAI's own or a vetted partner's agent).
    function mint(address to, bytes32 agentHash, uint256 score, string calldata metadataURI)
        external onlyOwner returns (uint256)
    {
        return passport.mint(to, agentHash, score, metadataURI);
    }

    function updateScore(uint256 tokenId, uint256 newScore) external onlyOwner {
        passport.updateScore(tokenId, newScore);
    }

    function revoke(uint256 tokenId) external onlyOwner {
        passport.revoke(tokenId);
    }

    function pausePassports() external onlyOwner { passport.pause(); }

    function unpausePassports() external onlyOwner { passport.unpause(); }

    /// @notice Second step of handing the SBT to this issuer.
    function acceptPassportOwnership() external onlyOwner { passport.acceptOwnership(); }

    /// @notice Hand the SBT to another owner (it must then call acceptOwnership on the SBT).
    function transferPassportOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert ZeroAddress();
        passport.transferOwnership(newOwner);
    }
}
