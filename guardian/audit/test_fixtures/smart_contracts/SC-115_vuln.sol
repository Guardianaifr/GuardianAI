pragma solidity ^0.8.0;
interface IRouter {
    function swapExactTokensForTokens(uint amountIn, uint amountOutMin, address[] calldata path, address to, uint deadline) external;
    function swapTokensForExactTokens(uint amountOut, uint amountInMax, address[] calldata path, address to, uint deadline) external;
}
contract SC115_Vuln {
    address[] path;
    address to;
    function swap(uint amount) external {
        IRouter(address(0)).swapExactTokensForTokens(amount, 0, path, to, 0);
    }
}
