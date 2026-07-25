@external
@nonreentrant('lock')
def withdraw(amount: uint256):
    self.balance -= amount