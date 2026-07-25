function mint(address to, uint256 amt) external {
  require(totalMinted + amt <= LIMIT);
  _mint(to, amt);
}