pragma solidity ^0.8.0;
contract SC120_Safe {
    function payout(address payable user) external {
        (bool ok, ) = user.call{value: 1 ether}("");
        require(ok);
    }
}