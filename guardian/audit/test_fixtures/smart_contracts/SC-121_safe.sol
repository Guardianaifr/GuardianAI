pragma solidity ^0.8.0;
contract SC121_Safe {
    address public owner;
    event OwnerSet(address indexed newOwner);
    function setOwner(address newOwner) external {
        owner = newOwner;
        emit OwnerSet(newOwner);
    }
}