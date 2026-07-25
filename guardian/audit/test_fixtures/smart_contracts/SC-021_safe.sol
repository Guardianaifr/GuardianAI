pragma solidity ^0.8.0;
contract SC021_Safe {
    function sub(uint a, uint b) public pure returns (uint) {
        require(b <= a);
        return a - b;
    }
}