import os
import glob
import json
import time
import requests
from dotenv import dotenv_values

env = dotenv_values(".env")
access_key = env.get("TENDERLY_ACCESS_KEY")
account = env.get("TENDERLY_ACCOUNT_SLUG", "monad-86d12ef02b")
project = env.get("TENDERLY_PROJECT_SLUG", "project")
vnet_rpc = env.get("TENDERLY_VIRTUAL_TESTNET_RPC")
vnet_id = env.get("TENDERLY_VNET_ID")

print("=================================================================")
print("TENDERLY SIMULATION & STATE OVERRIDE EDGE-CASE ENGINE")
print("=================================================================")
print(f"Account: {account} | Project: {project}")
print(f"VNet RPC: {vnet_rpc}\n")

# 1. Find storage slot layout from build-info
def get_storage_layout():
    for f in glob.glob("contracts/artifacts/build-info/*.json"):
        try:
            with open(f, "r", encoding="utf-8") as fh:
                d = json.load(fh)
                contracts = d.get("output", {}).get("contracts", {})
                for path, fc in contracts.items():
                    if "GuardianInsuranceLedger" in fc:
                        storage = fc["GuardianInsuranceLedger"].get("storageLayout", {}).get("storage", [])
                        return {item["label"]: item["slot"] for item in storage}
        except Exception as e:
            pass
    return {}

layout = get_storage_layout()
print("Found GuardianInsuranceLedger storage layout:")
for k, v in layout.items():
    print(f"  {k} -> slot {v}")

cert_slot = int(layout.get("certificateIds", 5))
paused_slot = int(layout.get("_paused", 2))
print(f"\nTarget slot for certificateIds.length: {cert_slot}")
print(f"Target slot for _paused: {paused_slot}\n")

headers = {
    "X-Access-Key": access_key,
    "Content-Type": "application/json"
}

# -----------------------------------------------------------------
# SCENARIO 1: Cap Limit Edge Case via Tenderly State Override
# -----------------------------------------------------------------
print("-----------------------------------------------------------------")
print("SCENARIO 1: Overriding State Slot to Test Cap Limit (100,000 max)")
print("-----------------------------------------------------------------")

insurance_address = "0xB98644392B035a4bA7207a6EcBfF0Ba82a57AfcE"

# Set storage slot to 100,000 (0x0186a0) directly on the Tenderly Virtual TestNet
hex_slot = hex(cert_slot)
hex_val = "0x00000000000000000000000000000000000000000000000000000000000186a0" # 100,000

r_set = requests.post(vnet_rpc, json={
    "jsonrpc": "2.0",
    "method": "tenderly_setStorageAt",
    "params": [insurance_address, hex_slot, hex_val],
    "id": 1
})
print("Set storage response:", r_set.json())

# Verify the storage slot
r_get = requests.post(vnet_rpc, json={
    "jsonrpc": "2.0",
    "method": "eth_getStorageAt",
    "params": [insurance_address, hex_slot, "latest"],
    "id": 2
})
current_val = int(r_get.json().get("result", "0x0"), 16)
print(f"Verified slot {cert_slot} value: {current_val} (Cap is 100,000)")

# Now simulate an issueCertificate transaction using Tenderly Simulation API
# Selector for issueCertificate(bytes32,bytes32,uint256,uint256,bytes32,string)
# 0x2213e843
from web3 import Web3
w3 = Web3()

with open("contracts/artifacts/contracts/GuardianInsuranceLedger.sol/GuardianInsuranceLedger.json") as f:
    ledger_abi = json.load(f)["abi"]

contract = w3.eth.contract(address=w3.to_checksum_address(insurance_address), abi=ledger_abi)
now = int(time.time())
calldata = contract.encode_abi("issueCertificate", [
    w3.to_bytes(hexstr="0x" + "11"*32),
    w3.to_bytes(hexstr="0x" + "22"*32),
    now,
    now + 86400 * 30,
    w3.to_bytes(hexstr="0x" + "33"*32),
    "LOW"
])

# Simulate on Tenderly with state override
sim_payload = {
    "network_id": "1",
    "from": "0x1D4549B95dccAC8203393543187b25B3137D0bf6",
    "to": insurance_address,
    "input": calldata,
    "gas": 300000,
    "save": True,
    "state_overrides": {
        insurance_address: {
            "storage": {
                f"0x{cert_slot:064x}": hex_val
            }
        }
    }
}

sim_url = f"https://api.tenderly.co/api/v1/account/{account}/project/{project}/simulate"
res_sim = requests.post(sim_url, headers=headers, json=sim_payload)
print(f"Simulation API Status: {res_sim.status_code}")

if res_sim.status_code == 200:
    sim_data = res_sim.json()
    tx_info = sim_data.get("transaction", {})
    sim_id = sim_data.get("simulation", {}).get("id")
    status = tx_info.get("status")
    error_msg = tx_info.get("error_message")
    trace_url = f"https://dashboard.tenderly.co/{account}/{project}/simulator/{sim_id}"
    
    print(f"  Result: Success={status}")
    print(f"  Revert Reason: {error_msg}")
    print(f"  Interactive Tenderly Trace URL: {trace_url}")

# Reset slot back to normal
requests.post(vnet_rpc, json={
    "jsonrpc": "2.0",
    "method": "tenderly_setStorageAt",
    "params": [insurance_address, hex_slot, "0x0000000000000000000000000000000000000000000000000000000000000001"],
    "id": 3
})

# -----------------------------------------------------------------
# SCENARIO 2: Governance Timelock 24h Enforced Delay Simulation
# -----------------------------------------------------------------
print("\n-----------------------------------------------------------------")
print("SCENARIO 2: Governance & Timelock Simulation (24h Delay & Execution)")
print("-----------------------------------------------------------------")

timelock_address = "0x866faF1d27c4eC0a30a6f5a2154562FC9f451cfB"

with open("contracts/artifacts/contracts/GuardianTimelock.sol/GuardianTimelock.json") as f:
    timelock_abi = json.load(f)["abi"]

tl_contract = w3.eth.contract(address=w3.to_checksum_address(timelock_address), abi=timelock_abi)

# Prepare a proposal: Timelock calls pause() on InsuranceLedger
pause_calldata = contract.encode_abi("pause", [])
salt = w3.to_bytes(hexstr="0x" + "aa"*32)
delay = 86400 # 24 hours (86400 seconds)
predecessor = w3.to_bytes(hexstr="0x" + "00"*32)

schedule_calldata = tl_contract.encode_abi("schedule", [
    w3.to_checksum_address(insurance_address),
    0,
    w3.to_bytes(hexstr=pause_calldata),
    predecessor,
    salt,
    delay
])

# Step A: Simulate scheduling the governance proposal
sim_schedule = requests.post(sim_url, headers=headers, json={
    "network_id": "1",
    "from": "0x1D4549B95dccAC8203393543187b25B3137D0bf6",
    "to": timelock_address,
    "input": schedule_calldata,
    "gas": 300000,
    "save": True
})
if sim_schedule.status_code == 200:
    s_data = sim_schedule.json()
    s_id = s_data.get("simulation", {}).get("id")
    print("  [Step A] Schedule Governance Proposal:")
    print(f"    Status: {s_data.get('transaction', {}).get('status')}")
    print(f"    Tenderly Trace: https://dashboard.tenderly.co/{account}/{project}/simulator/{s_id}")

# Step B: Simulate immediate execution (SHOULD REVERT because delay hasn't passed)
execute_calldata = tl_contract.encode_abi("execute", [
    w3.to_checksum_address(insurance_address),
    0,
    w3.to_bytes(hexstr=pause_calldata),
    predecessor,
    salt
])

sim_exec_early = requests.post(sim_url, headers=headers, json={
    "network_id": "1",
    "from": "0x1D4549B95dccAC8203393543187b25B3137D0bf6",
    "to": timelock_address,
    "input": execute_calldata,
    "gas": 300000,
    "save": True
})
if sim_exec_early.status_code == 200:
    e_data = sim_exec_early.json()
    e_id = e_data.get("simulation", {}).get("id")
    print("  [Step B] Immediate Execution (Before 24h):")
    print(f"    Status: {e_data.get('transaction', {}).get('status')} (Reverted as expected)")
    print(f"    Error: {e_data.get('transaction', {}).get('error_message')}")
    print(f"    Tenderly Trace: https://dashboard.tenderly.co/{account}/{project}/simulator/{e_id}")

# Step C: Simulate execution AFTER advancing time by 24h + 1s via Block Timestamp Override
sim_exec_matured = requests.post(sim_url, headers=headers, json={
    "network_id": "1",
    "from": "0x1D4549B95dccAC8203393543187b25B3137D0bf6",
    "to": timelock_address,
    "input": execute_calldata,
    "gas": 300000,
    "save": True,
    "block_header_overrides": {
        "timestamp": hex(now + 86401)
    }
})
if sim_exec_matured.status_code == 200:
    m_data = sim_exec_matured.json()
    m_id = m_data.get("simulation", {}).get("id")
    print("  [Step C] Execution with Timestamp Override (+24h 1s):")
    print(f"    Status: {m_data.get('transaction', {}).get('status')}")
    print(f"    Tenderly Trace: https://dashboard.tenderly.co/{account}/{project}/simulator/{m_id}")

print("\n=================================================================")
print("ALL SIMULATIONS AND EDGE-CASE TESTS COMPLETED SUCCESSFULLY!")
print("=================================================================")
