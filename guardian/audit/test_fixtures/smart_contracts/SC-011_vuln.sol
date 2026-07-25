pragma solidity ^0.8.0;
contract SC011_Vuln {
    function swap(uint amount) external {
        // No slippage
    }
}