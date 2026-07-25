function withdraw() external {
  require(owner == tx.origin);
}