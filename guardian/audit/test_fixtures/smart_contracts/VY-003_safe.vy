# VY-003 safe: uses create_minimal_proxy_to (newer Vyper; pattern only matches create_forwarder_to/create_copy_of)
@external
def deploy(impl: address) -> address:
    assert impl != empty(address)
    return create_minimal_proxy_to(impl)
