pragma solidity ^0.8.0;
contract SC061_Safe {
    function getPrice() public view returns (uint) {
        return TWAP.consult();
    }
}