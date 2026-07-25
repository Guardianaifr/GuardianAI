function fetchPrice() public view returns (uint) {
  return price; // uses `price` (defined in wrapper) so Slither compiles and custom detector fires
}