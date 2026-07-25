pragma solidity ^0.8.0;
contract SC070_Evasion {
    address[] public users;
    function payout() public {
        uint i = 0;
        while(i < users.length) {
            payable(users[i]).transfer(1);
            i++;
        }
    }
}