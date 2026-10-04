"""Give GuardianAI's attestation signer its own key, separate from the deployer/owner key.

Why: if one key both signs approvals and owns the contracts, leaking it lets an attacker approve any
transaction AND rotate the contracts' signer. After this, the signer key can only sign approvals.

What it does (dry run unless --yes):
  1. generates a fresh signer key (or uses --key)
  2. backs up .env to .env.bak-<timestamp>
  3. PolicyGuard.setAttestationSigner(new)                       (sent from GUARDIAN_DEPLOYER_PRIVATE_KEY)
  4. setGuardianSigner(new) on every GuardianAgentWallet listed in metropolis/deployments-monad.json
     ("agentWallets") that the deployer owns
  5. writes GUARDIAN_ATTESTATION_SIGNER_KEY / GUARDIAN_ATTESTATION_SIGNER into .env
Restart the relay afterwards so it signs with the new key.

Usage: python tools/rotate_attestation_signer.py [--yes] [--key 0x...]
"""
import json, os, re, shutil, sys, time
from pathlib import Path

from eth_account import Account
from web3 import Web3

ROOT = Path(__file__).resolve().parent.parent
ENV = ROOT / ".env"
DEPLOYMENTS = ROOT / "metropolis" / "deployments-monad.json"


def load_env():
    env = {}
    for line in ENV.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            env[k.strip()] = v.strip().strip("'\"")
    return env


def set_env_values(values):
    text = ENV.read_text(encoding="utf-8")
    for k, v in values.items():
        pat = re.compile(rf"^{re.escape(k)}=.*$", re.M)
        text = pat.sub(f"{k}={v}", text) if pat.search(text) else text.rstrip("\n") + f"\n{k}={v}\n"
    ENV.write_text(text, encoding="utf-8")


def main():
    yes = "--yes" in sys.argv
    key = sys.argv[sys.argv.index("--key") + 1] if "--key" in sys.argv else None
    env = load_env()
    deployer = Account.from_key(env["GUARDIAN_DEPLOYER_PRIVATE_KEY"])
    new = Account.from_key(key) if key else Account.create()
    if new.address == deployer.address:
        sys.exit("Refusing: the new signer is the deployer key.")
    w3 = Web3(Web3.HTTPProvider(env.get("MONAD_TESTNET_RPC") or "https://testnet-rpc.monad.xyz"))
    dep = json.loads(DEPLOYMENTS.read_text(encoding="utf-8"))
    guard = Web3.to_checksum_address(env.get("GUARDIAN_POLICY_GUARD_CONTRACT_MONAD") or dep["contracts"]["GuardianPolicyGuard"])
    abi = [
        {"name": "owner", "type": "function", "stateMutability": "view", "inputs": [], "outputs": [{"type": "address"}]},
        {"name": "attestationSigner", "type": "function", "stateMutability": "view", "inputs": [], "outputs": [{"type": "address"}]},
        {"name": "setAttestationSigner", "type": "function", "stateMutability": "nonpayable", "inputs": [{"name": "s", "type": "address"}], "outputs": []},
        {"name": "setGuardianSigner", "type": "function", "stateMutability": "nonpayable", "inputs": [{"name": "s", "type": "address"}], "outputs": []},
    ]
    calls = [(guard, "setAttestationSigner")]
    for w in (dep.get("agentWallets") or {}).values():
        addr = Web3.to_checksum_address(w["wallet"] if isinstance(w, dict) else w)
        if w3.eth.contract(address=addr, abi=abi).functions.owner().call() == deployer.address:
            calls.append((addr, "setGuardianSigner"))

    pg = w3.eth.contract(address=guard, abi=abi)
    print(f"deployer/owner : {deployer.address}")
    print(f"current signer : {pg.functions.attestationSigner().call()}")
    print(f"new signer     : {new.address}")
    for addr, fn in calls:
        print(f"  will call {fn}({new.address}) on {addr}")
    if not yes:
        print("\nDry run. Re-run with --yes to apply.")
        return

    backup = ENV.with_name(f".env.bak-{time.strftime('%Y%m%d-%H%M%S')}")
    shutil.copy2(ENV, backup)
    print(f"backed up .env -> {backup.name}")
    nonce = w3.eth.get_transaction_count(deployer.address, "pending")
    for addr, fn in calls:
        c = w3.eth.contract(address=addr, abi=abi)
        tx = getattr(c.functions, fn)(new.address).build_transaction({
            "from": deployer.address, "nonce": nonce, "chainId": w3.eth.chain_id,
        })
        h = w3.eth.send_raw_transaction(deployer.sign_transaction(tx).raw_transaction)
        r = w3.eth.wait_for_transaction_receipt(h, timeout=120)
        print(f"  {fn} on {addr}: status={r.status} tx=https://testnet.monadscan.com/tx/0x{h.hex().removeprefix('0x')}")
        if r.status != 1:
            sys.exit("Transaction failed; .env NOT updated (backup kept).")
        nonce += 1
    set_env_values({"GUARDIAN_ATTESTATION_SIGNER_KEY": "0x" + new.key.hex().removeprefix("0x"),
                    "GUARDIAN_ATTESTATION_SIGNER": new.address})
    dep["attestationSigner"] = new.address
    DEPLOYMENTS.write_text(json.dumps(dep, indent=2) + "\n", encoding="utf-8")
    print(f"PolicyGuard signer now: {pg.functions.attestationSigner().call()}")
    print(".env updated. Restart the relay.")


if __name__ == "__main__":
    main()
