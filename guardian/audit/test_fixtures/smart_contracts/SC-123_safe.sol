pragma solidity ^0.8.0;
contract SC123_Safe {
    bytes32 public DOMAIN_SEPARATOR;
    function permit(address owner, address spender, uint value, uint deadline, uint8 v, bytes32 r, bytes32 s) external {
        require(DOMAIN_SEPARATOR != bytes32(0));
    }
}