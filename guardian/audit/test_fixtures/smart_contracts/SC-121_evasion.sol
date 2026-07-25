pragma solidity ^0.8.0;
contract SC121_Evasion {
    address public owner;
    function changeOwner(address newOwner) external {
        owner = newOwner;
    }
}