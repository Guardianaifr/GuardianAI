function kill() external {
  destroyLogic.delegatecall("");
}