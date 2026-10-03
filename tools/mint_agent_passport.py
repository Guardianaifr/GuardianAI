"""Give an agent a GuardianAI ID card (GuardianPassportSBT.mint) on Monad testnet.

The card is keyed by keccak256("privy-agent:<address>"), the agent_id the Privy agent sends to the
relay. It's minted to the team wallet (the deployer), so the explorer's "outside teams" counter is
not inflated by our own agent. Needs GUARDIAN_DEPLOYER_PRIVATE_KEY (owner of PassportSBT) in .env.

Usage: python tools/mint_agent_passport.py <agent_wallet_address> [--yes]
Without --yes it only prints what it would do.
"""
import os, sys
from pathlib import Path
from web3 import Web3
from eth_account import Account

ROOT = Path(__file__).resolve().parent.parent
for line in (ROOT / ".env").read_text(encoding="utf-8").splitlines():
    line = line.strip()
    if line and not line.startswith("#") and "=" in line:
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip().strip("'\""))

PASSPORT = "0xDA5f4E1cC2174A75dA63BD37606D2b7960862Cff"
ABI = [
    {"name": "mint", "type": "function", "stateMutability": "nonpayable",
     "inputs": [{"name": "_to", "type": "address"}, {"name": "_agentHash", "type": "bytes32"},
                {"name": "_score", "type": "uint256"}, {"name": "_metadataURI", "type": "string"}],
     "outputs": [{"name": "", "type": "uint256"}]},
    {"name": "isPassportActive", "type": "function", "stateMutability": "view",
     "inputs": [{"name": "_agentId", "type": "bytes32"}], "outputs": [{"name": "", "type": "bool"}]},
]

if len(sys.argv) < 2:
    sys.exit(__doc__)
agent = Web3.to_checksum_address(sys.argv[1])
agent_id = f"privy-agent:{agent.lower()}"
agent_hash = Web3.keccak(text=agent_id)
w3 = Web3(Web3.HTTPProvider(os.environ.get("MONAD_TESTNET_RPC") or "https://testnet-rpc.monad.xyz"))
c = w3.eth.contract(address=PASSPORT, abi=ABI)
print("agent_id:", agent_id, "\nagentHash:", agent_hash.hex())
if c.functions.isPassportActive(agent_hash).call():
    sys.exit("already has an active ID card")
owner = Account.from_key(os.environ["GUARDIAN_DEPLOYER_PRIVATE_KEY"])
print("mint to (team wallet):", owner.address)
if "--yes" not in sys.argv:
    sys.exit("dry run: add --yes to send the mint transaction")
tx = c.functions.mint(owner.address, agent_hash, 5000, f"guardianai:privy-agent:{agent.lower()}").build_transaction({
    "from": owner.address, "nonce": w3.eth.get_transaction_count(owner.address), "chainId": 10143,
})
signed = owner.sign_transaction(tx)
h = w3.eth.send_raw_transaction(signed.raw_transaction)
r = w3.eth.wait_for_transaction_receipt(h)
print("status", r.status, "block", r.blockNumber, f"https://testnet.monadscan.com/tx/{h.hex() if h.hex().startswith('0x') else '0x' + h.hex()}")
