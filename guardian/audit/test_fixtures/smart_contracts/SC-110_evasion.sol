pragma solidity ^0.8.0;
library ECDSA {
    function recover(bytes32 hash, uint8 v, bytes32 r, bytes32 s) internal pure returns (address) {}
}
contract SC110_Evasion {
    function verify(bytes32 hash, uint8 v, bytes32 r, bytes32 s) public pure returns (address) {
        return ECDSA.recover(hash, v, r, s);
    }
}