pragma solidity ^0.8.0;
contract SC040_Vuln {
    function sendEth(address target) public {
        target.call("");
    }
}