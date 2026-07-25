pragma solidity ^0.8.0;
contract SC134_Vuln {
    function set(uint v) public {
        assembly { tstore(0, v) }
    }
}