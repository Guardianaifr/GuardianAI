pragma solidity ^0.8.0;
contract SC121_Vuln {
    address public owner;
    function setOwner(address newOwner) external {
        owner = newOwner;
    }
}