pragma solidity ^0.8.0;
contract SC120_Evasion {
    function payout(address payable user) external {
        user.call{gas: 2300}("");
    }
}