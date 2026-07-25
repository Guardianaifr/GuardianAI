pragma solidity ^0.8.0;
contract SC117_Vuln {
    function totalAssets() public view returns (uint) { return 0; }
    function donate() external {}
}