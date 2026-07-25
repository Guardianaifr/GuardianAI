@external
def transfer_eth(target: address):
    raw_call(target, b"", value=100)