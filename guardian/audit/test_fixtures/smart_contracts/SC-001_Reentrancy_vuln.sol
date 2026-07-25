function withdraw() public {
  msg.sender.call{value: 100}("");
  balances[msg.sender] = 0;
}