// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

interface IVault {
    function deposit(uint256 amount) external;
}

contract MaliciousToken is ERC20 {
    address public vault;
    bool public isReentering;

    constructor() ERC20("Malicious", "MAL") {}

    function setVault(address _vault) external {
        vault = _vault;
        // Approve the vault to spend tokens from THIS contract, so the re-entrant transfer succeeds
        _approve(address(this), vault, type(uint256).max);
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    function transferFrom(address from, address to, uint256 amount) public override returns (bool) {
        if (!isReentering && vault != address(0) && msg.sender == vault) {
            isReentering = true;
            // Attempt to re-enter
            IVault(vault).deposit(amount);
            isReentering = false;
        }
        return super.transferFrom(from, to, amount);
    }
}