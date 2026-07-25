pragma solidity ^0.8.0;
contract SC106_Safe {
    uint public totalSupply = 100;
    mapping(address => uint) public userCollateral;
    function depositCollateral(uint amount) external {
        require(totalSupply > 0);
        userCollateral[msg.sender] += amount;
    }
}