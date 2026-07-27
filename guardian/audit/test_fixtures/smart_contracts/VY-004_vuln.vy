# VY-004 vuln: uses shift() which can overflow on large shift counts
@external
def compute(x: uint256, n: uint256) -> uint256:
    return shift(x, convert(n, int128))
