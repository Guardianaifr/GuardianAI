import os
import requests
from dotenv import dotenv_values

env = dotenv_values(".env")
key = env["TENDERLY_ACCESS_KEY"]
acc = env["TENDERLY_ACCOUNT_SLUG"]
proj = env["TENDERLY_PROJECT_SLUG"]

testnets = [
    ("Monad Testnet (int)", 10143),
    ("Monad Testnet (str)", "10143"),
    ("Monad Mainnet (int)", 143),
    ("Sepolia", 11155111),
    ("Arbitrum Sepolia", 421614),
    ("Base Sepolia", 84532),
    ("Optimism Sepolia", 11155420),
    ("Polygon Amoy", 80002),
    ("Ethereum Mainnet", 1),
    ("Polygon Mainnet", 137),
    ("Arbitrum One", 42161),
    ("Base Mainnet", 8453),
    ("Optimism Mainnet", 10),
    ("BNB Chain", 56)
]

for name, nid in testnets:
    payload = {
        "slug": f"test-vnet-{str(nid).lower()}",
        "display_name": f"VNet {name}",
        "fork_config": {"network_id": nid},
        "virtual_network_config": {"chain_config": {"chain_id": int(nid) if str(nid).isdigit() else 1}}
    }
    r = requests.post(
        f"https://api.tenderly.co/api/v1/account/{acc}/project/{proj}/vnets",
        headers={"X-Access-Key": key, "Content-Type": "application/json"},
        json=payload
    )
    if r.status_code in [200, 201]:
        print(f"[AVAILABLE] {name}: SUCCESS (status {r.status_code})")
        v_id = r.json().get("id")
        requests.delete(f"https://api.tenderly.co/api/v1/account/{acc}/project/{proj}/vnets/{v_id}", headers={"X-Access-Key": key})
    else:
        err = r.json().get("error", {})
        print(f"[RESTRICTED] {name}: status {r.status_code} - {err.get('message')}")
