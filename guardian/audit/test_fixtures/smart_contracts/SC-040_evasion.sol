pragma solidity ^0.8.0;
contract SC040_Evasion {
    function sendEth(address target) public {
        bool res = target.call("");
    }
}