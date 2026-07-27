# VY-005 vuln: bare send() without assert wrapper
@external
def withdraw(to: address, amount: uint256):
    send(to, amount)
