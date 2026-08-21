// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IGuardianThreatFeed {
    function isMalicious(address _query) external view returns (bool, string memory);
    function isMaliciousString(string calldata _query) external view returns (bool, string memory);
}
