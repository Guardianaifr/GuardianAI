# VY-001 safe: default function protected by @nonreentrant — breaks the @external\s+def pattern
@external
@nonreentrant("lock")
def __default__():
    send(msg.sender, self.balance)
