function getReserves() public view returns (uint, uint) {
  return (totalSupply, balances[owner]); // unprotected view returning financial data
}
