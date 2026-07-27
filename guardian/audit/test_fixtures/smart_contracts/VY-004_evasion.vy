# VY-004 evasion: uses unsafe_shift (prefixed variant; same overflow risk)
@external
def compute(x: uint256, n: int128) -> uint256:
    return unsafe_shift(x, n)
