// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";

interface IGuardianPassportSBT {
    function mint(address _to, bytes32 _agentHash, uint256 _score, string calldata _metadataURI) external returns (uint256);
    function agentToken(bytes32) external view returns (uint256);
    function acceptOwnership() external;
}

/**
 * @title PassportMintAttacker
 * @notice Test helper that acts as both the SBT owner and mint recipient.
 *         In onERC721Received it attempts to double-mint the same agentHash.
 *
 *         With the CEI fix: agentToken[agentHash] is already committed before
 *         the callback fires, so the reentrant mint() reverts with
 *         AgentAlreadyHasPassport.
 *
 *         Without the CEI fix: agentToken[agentHash] would still be 0 during
 *         the callback, allowing the double-mint to succeed.
 */
contract PassportMintAttacker is IERC721Receiver {
    IGuardianPassportSBT public sbt;
    bytes32 public agentHash;

    // State observed during the onERC721Received callback
    uint256 public agentTokenDuringCallback;  // should be nonzero (CEI fix)
    bool    public reentrancyAttempted;
    bool    public reentrancySucceeded;       // must remain false

    constructor(address _sbt) {
        sbt = IGuardianPassportSBT(_sbt);
    }

    /// @notice Step 1: accept the ownership transfer from the original owner.
    function acceptSBTOwnership() external {
        sbt.acceptOwnership();
    }

    /// @notice Step 2: trigger the attack — mint to self (this contract).
    function attack(bytes32 _agentHash) external {
        agentHash = _agentHash;
        sbt.mint(address(this), _agentHash, 5000, "ipfs://original");
    }

    /// @notice Called by ERC-721 during _safeMint when this contract receives the token.
    function onERC721Received(
        address,
        address,
        uint256,
        bytes calldata
    ) external override returns (bytes4) {
        // Record what the SBT's mapping shows DURING the callback.
        // With CEI fix → nonzero (already committed).
        // Without fix   → zero (double-mint possible).
        agentTokenDuringCallback = sbt.agentToken(agentHash);

        // Attempt a double-mint of the same agentHash.
        reentrancyAttempted = true;
        try sbt.mint(address(this), agentHash, 9000, "ipfs://double-mint") {
            reentrancySucceeded = true;  // should NOT happen with CEI fix
        } catch {
            reentrancySucceeded = false;
        }

        return IERC721Receiver.onERC721Received.selector;
    }
}

/**
 * @title RejectingReceiver
 * @notice Always reverts in onERC721Received.
 *         Used to verify that a failed _safeMint rolls back ALL state
 *         (passports, agentToken, activePassportCount) atomically.
 */
contract RejectingReceiver is IERC721Receiver {
    function onERC721Received(
        address,
        address,
        uint256,
        bytes calldata
    ) external pure override returns (bytes4) {
        revert("RejectingReceiver: token rejected");
    }
}
