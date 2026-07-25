function claim(bytes32 hash, uint8 v, bytes32 r, bytes32 s) external {
  require(seq[msg.sender] == 0);
  address signer = ecrecover(hash, v, r, s);
  balances[signer] += 100;
}