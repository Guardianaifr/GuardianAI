# VY-001 vuln: external default function without reentrancy guard
@external
def __default__():
    send(msg.sender, self.balance)
