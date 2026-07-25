function withdraw(uint amount) public {
  require(balances[msg.sender] >= amount, "insufficient");
  balances[msg.sender] -= amount;
}
