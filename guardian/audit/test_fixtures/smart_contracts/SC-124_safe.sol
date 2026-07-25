pragma solidity ^0.8.0;
contract SC124_Safe {
    uint public totalRewards = 100;
    uint public totalSupply = 10;
    function rewardPerToken() public view returns (uint) {
        return (totalRewards * 1e18) / totalSupply;
    }
}