@external
def rand() -> uint256:
    return VRF.getRandom()