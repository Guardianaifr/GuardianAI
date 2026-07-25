pragma solidity ^0.8.0;
contract SC010_Vuln {
    function swap() external payable {
        // Front-running risk
    }
}