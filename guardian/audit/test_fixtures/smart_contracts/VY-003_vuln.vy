# VY-003 vuln: uses deprecated create_forwarder_to without validation
@external
def deploy(impl: address) -> address:
    return create_forwarder_to(impl)
