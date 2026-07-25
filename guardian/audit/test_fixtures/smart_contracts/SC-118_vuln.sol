pragma solidity ^0.8.0;
contract SC118_Vuln {
    address public owner;
    function transferOwnership(address newOwner) external {
        owner = newOwner;
    }
}