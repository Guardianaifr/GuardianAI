pragma solidity ^0.8.0;
contract SC134_Evasion {
    function set(uint v) public {
        assembly { sstore(0, v) }
    }
}