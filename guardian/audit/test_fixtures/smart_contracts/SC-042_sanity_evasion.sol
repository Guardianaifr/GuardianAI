function kill() public {
  destroyContract.delegatecall(""); // undefined target => Slither fails => regex catches empty-delegatecall pattern
}
