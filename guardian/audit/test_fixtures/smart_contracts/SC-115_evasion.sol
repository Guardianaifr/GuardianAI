pragma solidity ^0.8.0;
contract SC115_Evasion {
    function swap(uint amount) external {
        IRouter(address(0)).swapTokensForExactTokens(amount, 0, path, to, 0);
    }
}