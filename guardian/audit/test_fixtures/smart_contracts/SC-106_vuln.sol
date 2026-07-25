pragma solidity ^0.8.0;
contract SC106_Vuln {
    mapping(address => uint) public userCollateral;
    function depositCollateral(uint amount) external {
        userCollateral[msg.sender] += amount;
    }
}