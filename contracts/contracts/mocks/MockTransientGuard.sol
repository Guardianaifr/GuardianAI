// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";

contract MockTransientGuard is ReentrancyGuardTransient {
    uint256 public counter;

    event ProtectedActionExecuted(address indexed caller, uint256 count);

    function doProtectedWork(uint256 val) external nonReentrant returns (uint256) {
        counter += val;
        emit ProtectedActionExecuted(msg.sender, counter);
        return counter;
    }
}
