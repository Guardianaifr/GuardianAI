// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MockTargetContract {
    uint256 public counter;
    uint256 public lastReceivedValue;

    error MockTargetCustomError(uint256 errorCode);

    event Executed(address indexed sender, uint256 value, uint256 counter);

    function doSomething(uint256 x) external returns (uint256) {
        counter += x;
        emit Executed(msg.sender, 0, counter);
        return counter;
    }

    function doSomethingPayable() external payable returns (uint256) {
        lastReceivedValue = msg.value;
        counter += 1;
        emit Executed(msg.sender, msg.value, counter);
        return address(this).balance;
    }

    function alwaysReverts(string calldata reason) external pure {
        revert(reason);
    }

    function customErrorReverts(uint256 code) external pure {
        revert MockTargetCustomError(code);
    }

    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }

    receive() external payable {
        lastReceivedValue = msg.value;
    }
}