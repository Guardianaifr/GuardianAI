function roll() external {
  uint t = block.timestamp;
  if (t % 2 == 0) win();
}