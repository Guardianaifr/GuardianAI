pragma solidity ^0.8.0;
contract SC010_Safe {
    function swap(uint minOut, uint deadline) external payable {
        require(block.timestamp <= deadline);
    }
}