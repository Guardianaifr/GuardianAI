pragma solidity ^0.8.0;
contract SC115_Vuln {
    function swap(uint amount) external {
        IRouter(address(0)).swapExactTokensForTokens(amount, 0, path, to, 0);
    }
}