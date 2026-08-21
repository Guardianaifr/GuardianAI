// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IGuardianRiskAttestation {
    struct Attestation {
        uint16  score;           // 0–10000 (e.g. 9500 = 95.00%)
        string  grade;           // e.g. "A", "B+", "F"
        bytes32 signalsHash;     // keccak256 of the full signals JSON/metadata
        uint256 attestedAt;
        uint256 blockNumber;
    }

    function getAttestation(address _contractAddress, string calldata _chain)
        external view returns (Attestation memory);
}
