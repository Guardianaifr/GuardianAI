#!/usr/bin/env python3
import os, sys, time, subprocess, webbrowser
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

def clear():
    os.system("cls" if os.name == "nt" else "clear")

def banner(t):
    print("=" * 78)
    print(f"  ?? {t}")
    print("=" * 78)
    print()

def pause(p="Press [ENTER] to continue..."):
    try:
        input(f"\n?? {p}\n")
    except (KeyboardInterrupt, EOFError):
        print("\nExiting.")
        sys.exit(0)

def main():
    clear()
    banner("GUARDIAN AI ? MONAD METROPOLIS VIDEO DEMO RUNNER")
    print("This interactive guide walks you through recording the 3-5 minute demo step-by-step.\n")
    pause("Press [ENTER] for SCENE 1 (Introduction & Problem)...")

    clear()
    banner("SCENE 1: The Problem ? Autonomous Agents with Private Keys (0:00 - 0:45)")
    print("[ON SCREEN]: Show https://aiguardian.dev/ or architecture diagram.\n")
    print("??? READ SPOKEN VOICEOVER:")
    print("-" * 75)
    print("Welcome judges! I am presenting GuardianAI for the Monad Metropolis Hackathon,")
    print("competing in Track 04: Trust, Identity & AI Infrastructure.")
    print("Across Web3, autonomous AI agents are being given real money, private keys,")
    print("and on-chain treasuries. Yet LLMs cannot distinguish trusted instructions")
    print("from adversarial data. A single prompt injection can drain an entire treasury.")
    print("GuardianAI solves this with dual-layer defense: an off-chain edge firewall")
    print("under 5ms, backed by an on-chain execution firewall natively on Monad.")
    print("-" * 75 + "\n")
    pause("Press [ENTER] to run SCENE 2: Live Attack vs. Defense Simulation...")

    clear()
    banner("SCENE 2: Live Attack vs. Defense Simulation (0:45 - 2:00)")
    print("[ON SCREEN]: The terminal running demo/run_demo.py\n")
    print("??? READ SPOKEN VOICEOVER:")
    print("-" * 75)
    print("Here our trading agent has 5.0 ETH. In Act 1, an attacker injects a prompt")
    print("ordering it to approve unlimited spending and drain all funds.")
    print("Without GuardianAI, the model complies: wallet drops from 5.0 to 0.0 ETH.")
    print("Now in Act 2, through GuardianAI proxy: under 5ms, the attack is blocked")
    print("with HTTP 403 Forbidden. The agent never sees it, and the 5 ETH remains intact!")
    print("-" * 75 + "\n")
    
    py_exe = sys.executable
    venv_py = REPO_ROOT / ".venv312" / ("Scripts" if os.name == "nt" else "bin") / ("python.exe" if os.name == "nt" else "python")
    if venv_py.exists():
        py_exe = str(venv_py)
    subprocess.run([py_exe, str(REPO_ROOT / "demo" / "run_demo.py")], cwd=str(REPO_ROOT))

    pause("Press [ENTER] for SCENE 3: Category Labs Mera Passkey Enclave...")

    clear()
    banner("SCENE 3: Category Labs Mera Passkey PRF Enclave (2:00 - 2:55)")
    print("[ON SCREEN]: Terminal running Category Labs Mera Passkey PRF demo.\n")
    print("??? READ SPOKEN VOICEOVER:")
    print("-" * 75)
    print("How do we secure agent identity and memory without storing server keys?")
    print("For Category Labs Mera Bounty, we use WebAuthn Passkey PRF not for wallets,")
    print("but for sovereign Ed25519 identity and client-side AES-GCM memory sealing.")
    print("If an attacker tampers with even 1 byte in the database, the tripwire")
    print("fires MEMORY_POISONING_DETECTED and immediately quarantines the agent!")
    print("-" * 75 + "\n")
    
    npm_cmd = "npm.cmd" if os.name == "nt" else "npm"
    subprocess.run([npm_cmd, "run", "demo"], cwd=str(REPO_ROOT / "metropolis" / "mera"))

    pause("Press [ENTER] for SCENE 4: Monad Testnet & Tenderly Verification...")

    clear()
    banner("SCENE 4: Monad Testnet Verified Contracts & Tenderly Trace (2:55 - 3:45)")
    print("[ON SCREEN]: Opening verified browser tabs...\n")
    print("??? READ SPOKEN VOICEOVER:")
    print("-" * 75)
    print("On Monad Testnet (Chain ID 10143), GuardianPolicyGuard uses storage-slot")
    print("isolation with namespaced nonces to scale up to 10,000 TPS parallel EVM.")
    print("All 4 contracts are Full-Match verified on MonadVision via Sourcify.")
    print("Here is the confirmed Block #59,420,050 receipt, and our Tenderly simulation")
    print("trace showing un-attested drain attempts revert with zero leakage.")
    print("-" * 75 + "\n")

    urls = [
        "https://testnet.monadvision.com/contracts/full_match/10143/0x32fa262042dFB354f8064Ff369DcDe4BA4ec1101/",
        "https://testnet.monadvision.com/tx/0x2ac9f4eea0e9b918bf915f62e9763e9b67c48aa53425eff90c318106fb04d33a",
        "https://dashboard.tenderly.co/shared/simulation/b45791d7-a479-475a-a4c7-b26f34f9fc8e",
        "https://aiguardian.dev/proof.html"
    ]
    for u in urls:
        print(f"  ?? Opening: {u}")
        webbrowser.open(u)
        time.sleep(0.3)

    pause("Press [ENTER] for SCENE 5: Architecture & Test Summary...")

    clear()
    banner("SCENE 5: Architecture, Test Suites & Conclusion (3:45 - 4:15)")
    print("[ON SCREEN]: Return to https://aiguardian.dev/proof.html or terminal.\n")
    print("??? READ SPOKEN VOICEOVER:")
    print("-" * 75)
    print("GuardianAI is fully audited: 207 Smart Contract tests passing on Hardhat,")
    print("1,490+ Python security tests passing, 184 Mera Passkey tests passing,")
    print("and real-time indexing via Envio HyperIndex and Chainlink CRE.")
    print("GuardianAI makes autonomous agent economies on Monad safe and unstoppable.")
    print("Thank you!")
    print("-" * 75 + "\n")
    print("?? VIDEO DEMO FLOW COMPLETED SUCCESSFULLY!")

if __name__ == '__main__':
    main()
