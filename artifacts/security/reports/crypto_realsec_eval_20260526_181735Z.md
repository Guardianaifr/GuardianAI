# Crypto Real Security Evaluation

- Run at: `20260526_181735Z`
- Total cases: `16`
- Successful on-chain analyses: `15`
- Failed fetches: `1`
- Avg score (successful): `6.0`
- Trusted false-positive proxy rate: `1.0`

## Grade Distribution

- A: `0`
- B: `0`
- C: `0`
- D: `0`
- F: `15`

## Contract Results

- ETH USDC (ethereum): score `0.0`, grade `F`, high_risk `True`, top_rules `SC-001, SC-002, SC-020, SC-105, SC-118`
- ETH USDT (ethereum): score `0.0`, grade `F`, high_risk `True`, top_rules `SC-020, SC-100, SC-118, SC-120, SC-121`
- ETH WETH (ethereum): score `19.0`, grade `F`, high_risk `True`, top_rules `SC-020, SC-031, SC-120, SC-121, TK-011`
- ETH DAI (ethereum): score `0.0`, grade `F`, high_risk `True`, top_rules `SC-031, SC-110, SC-118, SC-121, SC-123`
- ETH UNI (ethereum): score `0.0`, grade `F`, high_risk `True`, top_rules `SC-020, SC-031, SC-111, SC-118, SC-121`
- ETH LINK (ethereum): score `34.0`, grade `F`, high_risk `True`, top_rules `SC-020, SC-118, SC-120, SC-121, TK-011`
- ETH Uniswap V2 Router (ethereum): score `0.0`, grade `F`, high_risk `True`, top_rules `SC-001, SC-010, SC-031, SC-060, SC-061`
- ETH Uniswap V3 Router (ethereum): score `0.0`, grade `F`, high_risk `True`, top_rules `SC-001, SC-020, SC-031, SC-041, SC-070`
- BSC BUSD (bsc): score `0.0`, grade `F`, high_risk `True`, top_rules `SC-100, SC-102, SC-118, SC-121, TK-001`
- BSC USDT (bsc): score `0.0`, grade `F`, high_risk `True`, top_rules `SC-100, SC-102, SC-118, SC-121, TK-001`
- BSC USDC (bsc): score `11.0`, grade `F`, high_risk `True`, top_rules `SC-020, SC-041, SC-105, SC-118, SC-121`
- BSC WBNB (bsc): score `19.0`, grade `F`, high_risk `True`, top_rules `SC-020, SC-031, SC-120, SC-121, TK-011`
- BSC CAKE (bsc): score `0.0`, grade `F`, high_risk `True`, top_rules `SC-001, SC-100, SC-102, SC-111, SC-118`
- BSC Pancake V2 Router (bsc): score `0.0`, grade `F`, high_risk `True`, top_rules `SC-001, SC-010, SC-020, SC-031, SC-061`
- MONAD USDC (monad): FAILED `Failed to retrieve source from Sourcify: Status 404`
- MONAD ExecutionInstallDelegate (monad): score `7.0`, grade `F`, high_risk `True`, top_rules `SC-010, SC-020, SC-021, SC-070, SC-105`

## Trust Guard Prompt Checks

- Unlimited approval: action `review` (expected `review_or_block`), deception `0.6`, confidence `0.65`
- Phishing wallet verify: action `block` (expected `review_or_block`), deception `0.9`, confidence `0.35`
- Known bad destination: action `review` (expected `review_or_block`), deception `0.4`, confidence `0.7`
- Benign prompt: action `allow` (expected `allow`), deception `0.0`, confidence `1.0`
