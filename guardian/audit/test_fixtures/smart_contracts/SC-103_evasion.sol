pragma solidity ^0.8.0;
contract SC103_Evasion {
    modifier onlyOwner() { _; }
    function issue(address to, uint amount) external onlyOwner {
        _mint(to, amount);
    }
    function _mint(address to, uint amount) internal {}
}