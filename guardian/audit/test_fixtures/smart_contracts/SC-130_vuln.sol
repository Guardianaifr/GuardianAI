pragma solidity ^0.8.0;
contract SC130_Vuln {
    function execute(address target) public {
        target.call("");
    }
}