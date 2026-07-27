# VY-005 safe: uses raw_call with explicit ETH transfer instead of the unsafe primitive
@external
def withdraw(to: address, amount: uint256):
    raw_call(to, b"", value=amount)
