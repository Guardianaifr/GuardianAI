pragma solidity ^0.8.0;
contract SC118_Safe {
    address public owner;
    function transferOwnership(address newOwner) external {
        require(newOwner != address(0));
        owner = newOwner;
    }
}