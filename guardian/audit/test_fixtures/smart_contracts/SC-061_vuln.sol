pragma solidity ^0.8.0;
contract SC061_Vuln {
    function getPrice() public view returns (uint) {
        (uint r0, uint r1, ) = IPool(address(0)).getReserves();
        return r0 / r1;
    }
}