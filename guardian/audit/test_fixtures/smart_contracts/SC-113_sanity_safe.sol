function getBalance() public view nonReentrant returns (uint) {
  return balances[msg.sender]; // nonReentrant protects this view
}
