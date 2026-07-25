pragma solidity ^0.8.0;
contract SC115_Safe {
    function swap(uint amount, uint deadline) external {
        require(block.timestamp <= deadline);
        IRouter(address(0)).swapExactTokensForTokens(amount, 0, path, to, deadline);
    }
}