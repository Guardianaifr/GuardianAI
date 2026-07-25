pragma solidity ^0.8.0;
contract SC130_Evasion {
    function execute(address target) public {
        assembly { let res := call(gas(), target, 0, 0, 0, 0, 0) }
    }
}