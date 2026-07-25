pragma solidity ^0.8.0;
contract SC002_Vuln {
    function withdraw(address payable to) external payable {
        to.call{value: msg.value}("");
    }
}