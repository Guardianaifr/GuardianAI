@external
def call_target(target: address):
    res: Bytes[32] = raw_call(target, b"", max_outsize=32)