pragma solidity ^0.8.0;
contract SC106_Evasion {
    mapping(address => uint) public userCollateral;
    function supplyCollateral(uint amount) external {
        userCollateral[msg.sender] += amount;
    }
}