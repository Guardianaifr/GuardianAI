pragma solidity ^0.8.0;
interface IReceiver { function receiveFunds() external payable; }
contract SC002_Evasion {
    function withdraw(address to) external payable {
        IReceiver(to).receiveFunds{value: msg.value}();
    }
}