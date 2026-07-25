function executeTrusted(bytes memory data) external {
  TRUSTED_TARGET.delegatecall(data);
}