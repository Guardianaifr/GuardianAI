pragma solidity ^0.8.0;
contract SC070_Safe {
    address[] public users;
    function payout(uint start, uint end) public {
        for(uint i=start; i<end; i++) {
            payable(users[i]).transfer(1);
        }
    }
}