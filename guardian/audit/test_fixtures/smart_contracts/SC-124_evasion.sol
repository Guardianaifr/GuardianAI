pragma solidity ^0.8.0;
contract SC124_Evasion {
    uint public rewards = 100;
    uint public stakedAmount = 10;
    function getPendingReward() public view returns (uint) {
        return rewards / stakedAmount;
    }
}