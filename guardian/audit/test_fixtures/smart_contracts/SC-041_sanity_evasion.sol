function proxy(address impl, bytes calldata d) public {
  impl.delegatecall(d); // user-controlled impl address — different param name from original
}
