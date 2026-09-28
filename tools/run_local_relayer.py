"""Local GuardianAI Attestation Relayer Service Daemon.

Runs GuardianRPCRelay and SafetyAttestationService on 127.0.0.1:8000
providing EIP-712 pre-flight safety attestation for @guardianai/middleware.
"""
import os
import sys
import logging
from pathlib import Path
from dotenv import load_dotenv

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(WORKSPACE_ROOT))

load_dotenv(WORKSPACE_ROOT / ".env")

from guardian.relayer.attestation_service import SafetyAttestationService, AgentPolicy
from guardian.web3sec.rpc_relay import GuardianRPCRelay

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("tools.run_local_relayer")

def create_relayer(port: int = 8000) -> GuardianRPCRelay:
    private_key = os.environ.get("GUARDIAN_ATTESTATION_SIGNER_KEY") or os.environ.get("GUARDIAN_DEPLOYER_PRIVATE_KEY")
    policy_guard = os.environ.get("GUARDIAN_POLICY_GUARD_CONTRACT_MONAD", "0x90Fdc8E1e5C951701eCd84677038B38560CdEF60")
    upstream_rpc = os.environ.get("MONAD_TESTNET_RPC", "https://testnet-rpc.monad.xyz")
    chain_id = int(os.environ.get("MONAD_CHAIN_ID", 10143))

    default_policies = {
        "eliza-victim-agent": AgentPolicy(
            max_value_per_tx=1000000000000000000,
            max_daily_outflow=5000000000000000000,
        ),
        "autonomous-trader-01": AgentPolicy(
            max_value_per_tx=2000000000000000000,
            max_daily_outflow=10000000000000000000,
        ),
    }

    service = SafetyAttestationService(
        private_key=private_key,
        verifying_contract=policy_guard,
        chain_id=chain_id,
        agent_policies=default_policies,
    )

    relay = GuardianRPCRelay({
        "web3_security": {
            "listen_port": port,
            "upstream_rpc": upstream_rpc,
            "fail_mode": "closed",
            "enforce_simulation": False,
        }
    })
    relay.attestation_service = service
    logger.info(f"Relayer initialized with signer: {service.signer_address}, Guard: {policy_guard}, Chain: {chain_id}")
    return relay

def main():
    port = int(os.environ.get("GUARDIAN_RELAYER_PORT", "8000"))
    relay = create_relayer(port=port)
    logger.info(f"Starting Guardian Attestation Relayer on 127.0.0.1:{port}...")
    try:
        from waitress import serve
        serve(relay.app, host="127.0.0.1", port=port, threads=8)
    except ImportError:
        relay.app.run(host="127.0.0.1", port=port, debug=False, use_reloader=False)

if __name__ == "__main__":
    main()
