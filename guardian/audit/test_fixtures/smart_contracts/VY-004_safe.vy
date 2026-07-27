# VY-004 safe: uses multiplication instead of shift; avoids shift/unsafe_shift
@external
def compute(x: uint256, n: uint256) -> uint256:
    return x * (2 ** n)
