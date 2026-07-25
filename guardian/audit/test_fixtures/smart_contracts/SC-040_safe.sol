pragma solidity ^0.8.0;
contract SC040_Safe {
    function sendEth(address target) public {
        (bool ok, ) = target.call("");
        require(ok);
    }
}