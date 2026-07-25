pragma solidity ^0.8.0;
interface IERC20 { function transfer(address to, uint amount) external returns (bool); }
abstract contract SC135_Vuln is IERC20 {
    function transfer(address to, uint amount) external virtual returns (bool);
}