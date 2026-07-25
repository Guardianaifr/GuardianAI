pragma solidity ^0.8.0;
contract SC061_Evasion {
    function fetchSpot() public view returns (uint) {
        (uint a, uint b) = IUniswap(address(0)).reserves();
        return a / b;
    }
}