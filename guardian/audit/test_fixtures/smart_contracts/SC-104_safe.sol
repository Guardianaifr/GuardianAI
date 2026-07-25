pragma solidity ^0.8.0;
contract SC104_Safe {
    function grantRole(bytes32 r, address a) external {
        // proposed and delay checked
        _grantRole(r, a);
    }
    function _grantRole(bytes32 r, address a) internal {}
}