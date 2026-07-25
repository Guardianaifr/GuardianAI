function withdraw() external {
  require(tx.origin == owner);
}