# GuardianAI Monad Security Dashboard

High-performance real-time telemetry dashboard for GuardianAI and Monad Parallel EVM security infrastructure.

## Features

- **Live On-Chain & Off-Chain Threat Telemetry:** Real-time push stream from GuardianAI security middleware and Envio HyperIndex GraphQL endpoint.
- **Standalone Live Web Mode:** Seamless zero-dependency live demonstration mode with graceful fallback/degradation for online hosting (e.g., `aiguardian.dev`) without requiring a local backend or indexer to be active.
- **Privy Autonomous Agent Containment:** Hardware-isolated session signer delegation, policy enforcement, and live execution simulation on Monad Testnet (Chain ID 10143).
- **MERA Enclave Integrity:** Attestation monitoring for deterministic passkey PRF Ed25519 agent identities and tamper-proof memory blocks.

## Environment Variables

Configure these in `dashboard/.env` or in your deployment platform:

| Variable | Description | Default |
|---|---|---|
| `VITE_PRIVY_APP_ID` | Privy Application ID for authentication and embedded wallets | `clx_guardian_demo` |
| `VITE_WS_URL` | WebSocket URL for live security threat feed | `ws://127.0.0.1:8001/ws/threats` (or `wss://${host}/ws/threats` on HTTPS) |
| `VITE_GRAPHQL_URL` | Envio HyperIndex GraphQL endpoint | `http://localhost:8080/v1/graphql` (or `${origin}/v1/graphql` on HTTPS) |
| `VITE_RELAYER_URL` | GuardianPolicyGuard attestation relayer base URL | `http://localhost:8000` |
| `VITE_STANDALONE_MODE` | Force standalone live simulation mode (`true` / `false`) | Auto-detected with graceful fallback |
| `VITE_AGENT_ADDRESS` | Monad testnet AI agent signer address | `0x742d35Cc6634C0532925a3b844Bc454e4438f44e` |
| `VITE_PRIVY_AGENT_POLICY_ID` | Scoped Privy delegation policy ID | `pol_guardian_monad_policyguard_01` |

## Getting Started

```bash
# Install dependencies
npm install

# Start development server
npm run dev

# Run ESLint checks
npm run lint

# Build for production
npm run build

# Preview production build
npm run preview
```
