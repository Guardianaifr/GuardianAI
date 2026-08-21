// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable2Step.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "./GuardianCircuitBreaker.sol";

/**
 * @title GuardianProtectedVault
 * @notice Reference implementation demonstrating how a DeFi protocol integrates
 *         Guardian circuit breaker protection. NOT intended for production deployment.
 *
 * @dev    This contract shows the integration pattern:
 *         1. Inherit GuardianCircuitBreaker
 *         2. Pass attestation and threat feed addresses to the constructor
 *         3. Apply guardianProtected or guardianProtectedStrict to sensitive functions
 *
 *         The vault accepts a single ERC-20 token for deposits/withdrawals.
 *         guardianProtected is used for normal operations (fail-open).
 *         guardianProtectedStrict is used for emergency operations (fail-closed).
 */
contract GuardianProtectedVault is GuardianCircuitBreaker, Ownable2Step, Pausable, ReentrancyGuard {
    using SafeERC20 for IERC20;

    IERC20 public immutable token;
    mapping(address => uint256) public balances;

    event Deposited(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);
    event EmergencyWithdrawn(address indexed owner, uint256 amount);

    error InsufficientBalance(uint256 requested, uint256 available);
    error ZeroAmount();

    constructor(
        address _token,
        address _riskAttestation,
        address _threatFeed
    )
        GuardianCircuitBreaker(_riskAttestation, _threatFeed, msg.sender)
        Ownable(msg.sender)
    {
        if (_token == address(0)) revert ZeroAddress();
        token = IERC20(_token);
    }

    function deposit(uint256 _amount) external guardianProtected whenNotPaused nonReentrant {
        if (_amount == 0) revert ZeroAmount();
        // CEI fix: safeTransferFrom before updating balances to prevent reentrancy via ERC777/hook tokens
        token.safeTransferFrom(msg.sender, address(this), _amount);
        balances[msg.sender] += _amount;
        emit Deposited(msg.sender, _amount);
    }

    function withdraw(uint256 _amount) external guardianProtected whenNotPaused nonReentrant {
        if (_amount == 0) revert ZeroAmount();
        if (balances[msg.sender] < _amount) {
            revert InsufficientBalance(_amount, balances[msg.sender]);
        }
        balances[msg.sender] -= _amount;
        token.safeTransfer(msg.sender, _amount);
        emit Withdrawn(msg.sender, _amount);
    }

    function emergencyWithdraw() external guardianProtectedStrict onlyOwner {
        uint256 bal = token.balanceOf(address(this));
        if (bal > 0) {
            token.safeTransfer(owner(), bal);
        }
        emit EmergencyWithdrawn(owner(), bal);
    }

    function pause() external onlyOwner { _pause(); }
    function unpause() external onlyOwner { _unpause(); }
}
