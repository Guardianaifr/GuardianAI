@external
def call_target(target: address):
    raw_call(target, b"", max_outsize=0)