// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MockDependencies {
    struct Attestation {
        uint16  score;
        string  grade;
        bytes32 signalsHash;
        uint256 attestedAt;
        uint256 blockNumber;
    }

    function getAttestation(address, string calldata) external view returns (Attestation memory) {
        return Attestation(9000, "A", bytes32(0), block.timestamp, block.number);
    }
    
    function isMalicious(address) external pure returns (bool, string memory) {
        return (false, "");
    }
    
    function isMaliciousString(string calldata) external pure returns (bool, string memory) {
        return (false, "");
    }
}