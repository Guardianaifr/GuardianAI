// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/governance/TimelockController.sol";

/**
 * @title GuardianTimelock
 * @notice Timelock controller for Guardian protocol admin operations.
 * All 6 Guardian contracts transfer ownership to this timelock,
 * enforcing a minimum 24-hour delay on all privileged operations.
 *
 * Roles:
 * - PROPOSER_ROLE: multi-sig wallet that proposes operations
 * - EXECUTOR_ROLE: address(0) = anyone can execute after delay. This is an intentional OpenZeppelin
 *   TimelockController pattern; security relies on the restricted proposer set, not the executor.
 * - CANCELLER_ROLE: same as proposer (can cancel pending ops)
 * - TIMELOCK_ADMIN_ROLE: renounced after setup (no admin backdoor)
 */
contract GuardianTimelock is TimelockController {
    uint256 public constant MIN_DELAY = 24 hours;

    constructor(
        address[] memory proposers,
        address[] memory executors,
        address admin
    )
        TimelockController(
            MIN_DELAY,
            proposers,
            executors,
            admin
        )
    {}
}
