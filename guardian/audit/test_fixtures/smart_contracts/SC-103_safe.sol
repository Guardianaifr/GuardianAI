pragma solidity ^0.8.0;
contract SC103_Safe {
    modifier onlyTimelock() { _; }
    function mint(address to, uint amount) external onlyTimelock {
        _mint(to, amount);
    }
    function _mint(address to, uint amount) internal {}
}