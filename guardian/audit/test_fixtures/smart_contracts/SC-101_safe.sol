function grantRole(bytes32 role, address account) public onlyGovDAO {
  _grantRole(role, account);
}