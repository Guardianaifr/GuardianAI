function withdraw() public {
  uint b = balances[msg.sender];
  balances[msg.sender] = 0;
  msg.sender.call{value: b}("");
}