import re

with open('contracts/contracts/GuardianProtectedVault.sol', 'r', encoding='utf-8') as f:
    content = f.read()

# Add ReentrancyGuard inheritance and import
if 'import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";' not in content:
    content = content.replace('import "@openzeppelin/contracts/access/Ownable.sol";', 'import "@openzeppelin/contracts/access/Ownable.sol";\nimport "@openzeppelin/contracts/utils/ReentrancyGuard.sol";')
    content = content.replace('contract GuardianProtectedVault is GuardianCircuitBreaker, Pausable, Ownable {', 'contract GuardianProtectedVault is GuardianCircuitBreaker, Pausable, Ownable, ReentrancyGuard {')

# Add nonReentrant to deposit and withdraw
old_deposit = 'function deposit(uint256 _amount) external guardianProtected whenNotPaused {'
new_deposit = 'function deposit(uint256 _amount) external guardianProtected whenNotPaused nonReentrant {'
content = content.replace(old_deposit, new_deposit)

old_withdraw = 'function withdraw(uint256 _amount) external guardianProtected whenNotPaused {'
new_withdraw = 'function withdraw(uint256 _amount) external guardianProtected whenNotPaused nonReentrant {'
content = content.replace(old_withdraw, new_withdraw)

with open('contracts/contracts/GuardianProtectedVault.sol', 'w', encoding='utf-8') as f:
    f.write(content)
