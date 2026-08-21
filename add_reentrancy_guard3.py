import re

with open('contracts/contracts/GuardianProtectedVault.sol', 'r', encoding='utf-8') as f:
    content = f.read()

content = content.replace('contract GuardianProtectedVault is GuardianCircuitBreaker, Ownable2Step, Pausable {', 'contract GuardianProtectedVault is GuardianCircuitBreaker, Ownable2Step, Pausable, ReentrancyGuard {')

with open('contracts/contracts/GuardianProtectedVault.sol', 'w', encoding='utf-8') as f:
    f.write(content)
