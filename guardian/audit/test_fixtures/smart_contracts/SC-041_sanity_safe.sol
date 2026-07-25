function callSelf(bytes memory data) external {
  address(this).delegatecall(data); // target is hardcoded address(this) — not user-supplied
}
