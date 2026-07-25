function execute(address target, bytes memory data) external {
  target.delegatecall(data);
}