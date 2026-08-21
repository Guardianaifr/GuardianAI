import re

with open('contracts/contracts/GuardianProtectedVault.sol', 'r', encoding='utf-8') as f:
    content = f.read()

old_deposit = '''    function deposit(uint256 _amount) external guardianProtected whenNotPaused {
        if (_amount == 0) revert ZeroAmount();
        balances[msg.sender] += _amount;
        token.safeTransferFrom(msg.sender, address(this), _amount);
        emit Deposited(msg.sender, _amount);
    }'''

new_deposit = '''    function deposit(uint256 _amount) external guardianProtected whenNotPaused {
        if (_amount == 0) revert ZeroAmount();
        // CEI fix: safeTransferFrom before updating balances to prevent reentrancy via ERC777/hook tokens
        token.safeTransferFrom(msg.sender, address(this), _amount);
        balances[msg.sender] += _amount;
        emit Deposited(msg.sender, _amount);
    }'''

content = content.replace(old_deposit, new_deposit)

with open('contracts/contracts/GuardianProtectedVault.sol', 'w', encoding='utf-8') as f:
    f.write(content)
