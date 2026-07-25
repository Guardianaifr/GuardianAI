pragma solidity ^0.8.0;
contract SC110_Safe {
    bytes32 public DOMAIN_SEPARATOR;
    function verify(bytes32 hash, uint8 v, bytes32 r, bytes32 s) public view returns (address) {
        bytes32 msgHash = keccak256(abi.encodePacked(hash, block.chainid, DOMAIN_SEPARATOR));
        return ecrecover(msgHash, v, r, s);
    }
}