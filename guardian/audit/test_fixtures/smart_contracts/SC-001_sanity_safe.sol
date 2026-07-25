function deposit(uint amount) public {
  require(amount > 0, "zero");
  balances[msg.sender] += amount;
  payable(address(this)).transfer(0); // transfer with no value — no reentrancy risk
}
