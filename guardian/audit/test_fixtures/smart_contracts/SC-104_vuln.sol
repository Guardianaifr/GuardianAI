pragma solidity ^0.8.0;
contract SC104_Vuln {
    function grantRole(bytes32 r, address a) external {
        _grantRole(r, a);
    }
    function _grantRole(bytes32 r, address a) internal {}
}