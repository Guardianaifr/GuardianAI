pragma solidity ^0.8.0;
interface TokenInterface { function transfer(address to, uint amount) external returns (bool); }
abstract contract SC135_Evasion is TokenInterface {
    function transfer(address to, uint amount) external virtual returns (bool);
}