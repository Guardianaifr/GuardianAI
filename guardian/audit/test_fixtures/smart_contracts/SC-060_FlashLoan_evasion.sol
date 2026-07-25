function doArb() external {
  pool.requestFlash(address(this), 100);
}