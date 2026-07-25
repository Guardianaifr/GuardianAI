@external
def get_time() -> uint256:
    t: uint256 = block.timestamp
    return t % 10