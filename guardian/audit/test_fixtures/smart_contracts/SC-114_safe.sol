function doAdd() external {
  require(checkSlippage());
  addLiquidity(a, b, c);
}