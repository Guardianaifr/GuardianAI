function drain(address[] memory targets) public {
  for (uint i = 0; i < targets.length; i++) {
    uint b = balances[targets[i]];
    // Reentrancy via loop: external call before zeroing, different from original
    (bool ok,) = targets[i].call{value: b}("");
    require(ok);
    balances[targets[i]] = 0; // state written AFTER external call in each iteration
  }
}
