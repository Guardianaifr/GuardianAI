@external
def payout(target: address):
    assert send(target, 100)