# GuardianAI Python Test Suite

## Setup

Run from the repository root with Python 3.12.

```bash
# macOS / Linux
python3.12 -m venv .venv312
source .venv312/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
```

```powershell
# Windows (PowerShell)
py -3.12 -m venv .venv312
.\.venv312\Scripts\python.exe -m pip install -r requirements.txt -r requirements-dev.txt
```

## Running tests

```bash
pytest                                            # whole suite (1,490+ tests); coverage report is on by default (pytest.ini)
pytest tests/guardrails/test_input_filter.py      # one file
pytest -m e2e                                     # full-stack proxy + backend tests only
pytest --no-cov tests/audit/test_smart_contract_analyzer.py   # run standalone: under coverage Slither falls back to regex detection
```

Coverage output goes to the terminal and to `htmlcov/` (git-ignored).

## Layout

| Folder / file | Covers |
|---|---|
| `guardrails/`, `security/`, `runtime/`, `proxy/` | The off-chain firewall: input/output filters, AI firewall, rate limiter, proxy |
| `backend/` | FastAPI control plane: auth, RBAC, routers |
| `audit/` | Smart-contract and token analyzers (Slither needs `solc` 0.8.24) |
| `brain/`, `compliance/`, `sdk/` | Red/blue/purple agents, EU AI Act tooling, Python SDK and agent middleware |
| `e2e/`, `stress/` | End-to-end stack and load tests |
| `test_rpc_relay*.py`, `test_attestation_service.py`, `test_cloud_relay.py` | Relay and EIP-712 approvals |
| `test_agent_wallet_attestation.py`, `test_agent_rules.py`, `test_agent_policies.py` | Agent-wallet approvals, per-agent rules, selector allowlists and outflow caps |
| `test_threat_oracle_feed.py` | Feed read by the Chainlink CRE workflow |
| `test_agent_card.py` | Mera passkey-signed agent cards |

The JavaScript/TypeScript suites (contracts, explorer, Mera, indexer, middleware, hosted agent) live in their own
folders; see [CONTRIBUTING.md](../CONTRIBUTING.md) and [docs/operations/VALIDATION.md](../docs/operations/VALIDATION.md).
