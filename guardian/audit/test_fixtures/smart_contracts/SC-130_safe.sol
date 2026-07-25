pragma solidity ^0.8.0;
contract SC130_Safe {
    function execute(address target) public {
        require(target.code.length > 0);
        target.call("");
    }
}