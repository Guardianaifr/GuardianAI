function mint(address to, uint amount) external requiresAuth {
  _mint(to, amount);
}