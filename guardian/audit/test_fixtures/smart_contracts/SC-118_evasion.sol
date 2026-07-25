pragma solidity ^0.8.0;
contract SC118_Evasion {
    address public owner;
    function changeOwner(address target) external {
        owner = target;
    }
}