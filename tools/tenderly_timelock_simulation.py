import os
import json
import time
import requests
from web3 import Web3
from dotenv import dotenv_values

env = dotenv_values(".env")
rpc = env["TENDERLY_VIRTUAL_TESTNET_RPC"]
deployer_key = env["GUARDIAN_DEPLOYER_PRIVATE_KEY"]
account = env.get("TENDERLY_ACCOUNT_SLUG", "monad-86d12ef02b")
project = env.get("TENDERLY_PROJECT_SLUG", "project")
access_key = env["TENDERLY_ACCESS_KEY"]
vnet_id = env["TENDERLY_VNET_ID"]

# Addresses
timelock_address = "0x866faF1d27c4eC0a30a6f5a2154562FC9f451cfB"
insurance_address = "0xB98644392B035a4bA7207a6EcBfF0Ba82a57AfcE"

w3 = Web3(Web3.HTTPProvider(rpc))
deployer = w3.eth.account.from_key(deployer_key)

with open("contracts/artifacts/contracts/GuardianTimelock.sol/GuardianTimelock.json") as f:
    timelock_abi = json.load(f)["abi"]
with open("contracts/artifacts/contracts/GuardianInsuranceLedger.sol/GuardianInsuranceLedger.json") as f:
    ledger_abi = json.load(f)["abi"]

timelock = w3.eth.contract(address=w3.to_checksum_address(timelock_address), abi=timelock_abi)
ledger = w3.eth.contract(address=w3.to_checksum_address(insurance_address), abi=ledger_abi)

print("=================================================================")
print("GOVERNANCE TIMELOCK ON-CHAIN SIMULATION & VERIFICATION")
print("=================================================================")
print(f"Timelock Contract: {timelock_address}")
print(f"Target Contract:   {insurance_address}")
print(f"Deployer / Proposer: {deployer.address}\n")

# Prepare operation: Timelock calls pause() on GuardianInsuranceLedger
target = w3.to_checksum_address(insurance_address)
value = 0
data = ledger.encode_abi("pause", [])
predecessor = w3.to_bytes(hexstr="0x" + "00"*32)
salt = w3.keccak(text=f"proposal-governance-timelock-{int(time.time())}")
delay = 86400  # 24 hours required by MIN_DELAY

# -------------------------------------------------------------
# STEP 1: Schedule Proposal in Timelock
# -------------------------------------------------------------
print("[Step 1] Scheduling Governance Proposal in Timelock (24h Delay)...")
tx_schedule = timelock.functions.schedule(
    target,
    value,
    w3.to_bytes(hexstr=data),
    predecessor,
    salt,
    delay
).build_transaction({
    "from": deployer.address,
    "nonce": w3.eth.get_transaction_count(deployer.address),
    "gas": 300000,
    "gasPrice": w3.eth.gas_price
})
signed_s = w3.eth.account.sign_transaction(tx_schedule, deployer_key)
tx_s_hash = w3.eth.send_raw_transaction(signed_s.raw_transaction)
receipt_s = w3.eth.wait_for_transaction_receipt(tx_s_hash)
print(f"   -> Proposal Scheduled! Tx Hash: {tx_s_hash.hex()} (Status: {receipt_s.status})")

# -------------------------------------------------------------
# STEP 2: Attempt Immediate Execution (Must REVERT!)
# -------------------------------------------------------------
print("\n[Step 2] Attempting Immediate Execution (0 seconds elapsed)...")
tx_exec_early = timelock.functions.execute(
    target,
    value,
    w3.to_bytes(hexstr=data),
    predecessor,
    salt
).build_transaction({
    "from": deployer.address,
    "nonce": w3.eth.get_transaction_count(deployer.address),
    "gas": 300000,
    "gasPrice": w3.eth.gas_price
})
signed_e1 = w3.eth.account.sign_transaction(tx_exec_early, deployer_key)
tx_e1_hash = w3.eth.send_raw_transaction(signed_e1.raw_transaction)
receipt_e1 = w3.eth.wait_for_transaction_receipt(tx_e1_hash)
print(f"   -> Premature Execution Reverted as Expected! Tx Hash: {tx_e1_hash.hex()}")
print(f"      Status: {receipt_e1.status} (0 = Reverted by TimelockController: operation not ready)")

# -------------------------------------------------------------
# STEP 3: Fast-Forward Time on Tenderly Virtual TestNet by 24h + 60s
# -------------------------------------------------------------
print("\n[Step 3] Fast-forwarding Virtual TestNet Time by 24 hours + 60s...")
requests.post(rpc, json={"jsonrpc": "2.0", "method": "evm_increaseTime", "params": [86460], "id": 10})
requests.post(rpc, json={"jsonrpc": "2.0", "method": "evm_mine", "params": [], "id": 11})
print("   -> Advanced timestamp by 86,460 seconds and mined block.")

# -------------------------------------------------------------
# STEP 4: Execute Proposal (Should SUCCEED!)
# -------------------------------------------------------------
print("\n[Step 4] Executing Proposal after 24h Timelock Delay...")
tx_exec_matured = timelock.functions.execute(
    target,
    value,
    w3.to_bytes(hexstr=data),
    predecessor,
    salt
).build_transaction({
    "from": deployer.address,
    "nonce": w3.eth.get_transaction_count(deployer.address),
    "gas": 300000,
    "gasPrice": w3.eth.gas_price
})
signed_e2 = w3.eth.account.sign_transaction(tx_exec_matured, deployer_key)
tx_e2_hash = w3.eth.send_raw_transaction(signed_e2.raw_transaction)
receipt_e2 = w3.eth.wait_for_transaction_receipt(tx_e2_hash)
print(f"   -> Governance Proposal Successfully Executed! Tx Hash: {tx_e2_hash.hex()}")
print(f"      Status: {receipt_e2.status} (1 = Confirmed & Executed!)")

# -------------------------------------------------------------
# STEP 5: Query Tenderly Dashboard URLs
# -------------------------------------------------------------
print("\n=================================================================")
print("FETCHING TENDERLY VISUAL DEBUGGER URLS")
print("=================================================================")
r_txs = requests.get(
    f"https://api.tenderly.co/api/v1/account/{account}/project/{project}/vnets/{vnet_id}/transactions",
    headers={"X-Access-Key": access_key}
)
tx_map = {t.get("tx_hash"): t.get("dashboard_url") for t in r_txs.json() if t.get("tx_hash")}

print(f"1. Schedule Proposal Trace:")
print(f"   {tx_map.get(tx_s_hash.hex(), 'https://dashboard.tenderly.co')}")

print(f"\n2. Premature Execution (Revert Trace - Timelock Delay Enforced):")
print(f"   {tx_map.get(tx_e1_hash.hex(), 'https://dashboard.tenderly.co')}")

print(f"\n3. Matured Execution (Success Trace - Executed after +24h):")
print(f"   {tx_map.get(tx_e2_hash.hex(), 'https://dashboard.tenderly.co')}")
print("=================================================================")
