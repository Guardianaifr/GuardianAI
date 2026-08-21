import re

with open('contracts/contracts/GuardianProtectedVault.sol', 'r', encoding='utf-8') as f:
    content = f.read()

# Add ReentrancyGuard inheritance and import
if 'import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";' not in content:
    content = content.replace('import "@openzeppelin/contracts/utils/Pausable.sol";', 'import "@openzeppelin/contracts/utils/Pausable.sol";\nimport "@openzeppelin/contracts/utils/ReentrancyGuard.sol";')
    content = content.replace('contract GuardianProtectedVault is GuardianCircuitBreaker, Pausable, Ownable {', 'contract GuardianProtectedVault is GuardianCircuitBreaker, Pausable, Ownable, ReentrancyGuard {')
    # Actually wait, I need to check what it actually inherits
    
content = content.replace('contract GuardianProtectedVault is GuardianCircuitBreaker, Pausable, Ownable2Step {', 'contract GuardianProtectedVault is GuardianCircuitBreaker, Pausable, Ownable2Step, ReentrancyGuard {')

with open('contracts/contracts/GuardianProtectedVault.sol', 'w', encoding='utf-8') as f:
    f.write(content)
