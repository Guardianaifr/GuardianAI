pragma solidity ^0.8.0;
contract SC021_Evasion {
    function sub(uint a, uint b) public pure returns (uint res) {
        assembly { res := sub(a, b) }
    }
}