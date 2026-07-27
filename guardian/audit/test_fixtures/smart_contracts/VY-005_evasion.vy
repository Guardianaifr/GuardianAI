# VY-005 evasion: conditional send without assert guard — still matches (?<!assert\s)send(
@external
def withdraw(to: address, amount: uint256):
    if amount > 0:
        send(to, amount)
