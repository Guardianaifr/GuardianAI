pragma solidity ^0.8.0;
contract SC134_Safe {
    mapping(uint => uint) storageSlot;
    function set(uint v) public {
        storageSlot[0] = v;
    }
}