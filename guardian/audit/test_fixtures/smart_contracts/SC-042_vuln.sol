function kill() external {
  selfdestruct(payable(owner));
}