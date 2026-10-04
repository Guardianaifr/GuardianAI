// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MockPassportRegistry {
    mapping(bytes32 => bool) public active;
    function setActive(bytes32 agentId, bool isActive) external { active[agentId] = isActive; }
    function isPassportActive(bytes32 agentId) external view returns (bool) { return active[agentId]; }
}
