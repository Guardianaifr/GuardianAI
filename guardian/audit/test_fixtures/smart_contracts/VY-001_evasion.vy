# VY-001 evasion: uses raw_call instead of send but still has unguarded __default__
@external
def __default__():
    raw_call(msg.sender, b"", value=self.balance)
