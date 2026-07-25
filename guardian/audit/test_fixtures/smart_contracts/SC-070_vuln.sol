pragma solidity ^0.8.0;
contract SC070_Vuln {
    address[] public users;
    function payout() public {
        for(uint i=0; i<users.length; i++) {
            payable(users[i]).transfer(1);
        }
    }
}