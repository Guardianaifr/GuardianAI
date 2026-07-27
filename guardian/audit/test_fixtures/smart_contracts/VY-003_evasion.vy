# VY-003 evasion: uses create_copy_of (same proxy risk, different function name)
@external
def deploy(impl: address) -> address:
    return create_copy_of(impl)
