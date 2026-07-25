function getPrice() public view returns (uint) {
  return median(oracle1, oracle2, oracle3);
}