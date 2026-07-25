pragma solidity ^0.8.0;
function add(uint a, uint b) public pure returns (uint) {
  return a + b; // 0.8.0+ has built-in overflow protection
}
