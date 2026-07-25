function doArb() external {
  pool.flashLoan(address(this), 100);
}