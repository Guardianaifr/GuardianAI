pragma solidity ^0.8.0;
contract SC123_Vuln {
    function permit(address owner, address spender, uint value, uint deadline, uint8 v, bytes32 r, bytes32 s) external {}
}