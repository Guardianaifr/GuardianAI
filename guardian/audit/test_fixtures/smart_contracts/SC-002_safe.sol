pragma solidity ^0.8.0;
contract SC002_Safe {
    bool private locked;
    modifier nonReentrant() { require(!locked); locked = true; _; locked = false; }
    function withdraw(address payable to) external payable nonReentrant {
        to.call{value: msg.value}("");
    }
}