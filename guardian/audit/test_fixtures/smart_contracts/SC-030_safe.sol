function check() external {
  require(tx.origin == msg.sender, "No contracts");
}