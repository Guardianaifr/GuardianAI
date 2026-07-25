function shutdown() external onlyOwner {
  selfdestruct(payable(owner));
}
