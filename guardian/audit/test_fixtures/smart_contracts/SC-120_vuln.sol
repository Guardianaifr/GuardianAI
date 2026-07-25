pragma solidity ^0.8.0;
contract SC120_Vuln {
    function payout(address payable user) external {
        user.transfer(1 ether);
    }
}