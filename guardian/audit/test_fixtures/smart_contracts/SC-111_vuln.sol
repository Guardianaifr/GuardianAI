function claim(bytes32 hash, uint8 v, bytes32 r, bytes32 s) external {
  address signer = ecrecover(hash, v, r, s);
  balances[signer] += 100;
}