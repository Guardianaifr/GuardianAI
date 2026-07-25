pragma solidity ^0.8.0;
interface IERC20 { function transfer(address to, uint amount) external returns (bool); }
contract SC135_Safe is IERC20 {
    function transfer(address to, uint amount) external override returns (bool) { return true; }
}