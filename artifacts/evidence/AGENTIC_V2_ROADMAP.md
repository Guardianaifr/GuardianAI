# Agentic Security V2 Roadmap
 
Status: Phase 2 implementation started

## Delivered in Phase 1

1. MCP trust boundary controls
- Trusted MCP server allowlist
- Optional requirement to declare MCP server on tool-invoking requests

2. MCP tool authorization
- Server-specific tool allowlist mapping (`mcp_server_tool_allowlist`)

3. Scope non-escalation control
- Parent scope vs requested scope enforcement with configurable hierarchy

## Phase 2 (Recommended Next)

1. Signed agent identity and attestation
- mTLS/JWT-backed agent identity attestation
- Per-agent key rotation and revocation support
- Implemented configurable HMAC/JWT-style signed attestation headers with timestamp freshness checks.
- Implemented per-agent key IDs plus agent/key revocation lists.
- Added backend control-plane APIs for issuing, rotating, listing, and revoking agent attestation keys.
- Added HS256 JWT-backed runtime attestation validation.
- Added reverse-proxy mTLS header binding with per-agent certificate fingerprint allowlists.

2. Cross-agent policy graph
- Parent-child capability graph with deny-by-default for transitive tool hops
- Time-bounded execution grants
- Implemented configurable cross-agent policy graph with scoped tool/hop constraints.
- Implemented execution grants with expiration, agent/parent binding, scope limits, and tool limits.
- Added backend APIs for policy graph edge management and execution grant lifecycle management.

3. Execution trace integrity
- Immutable chain-of-custody event hash for tool-step sequences
- Tamper-evident replay validation
- Implemented deterministic tool-step trace hash validation and optional replay cache.
- Added persisted trace hash table and config snapshot export path for replay validation state.

4. Risk-adaptive runtime controls
- Dynamic scope tightening based on threat score
- Automatic kill-switch escalation by policy severity
- Implemented threat-score header handling with dynamic scope tightening and high-risk kill-switch blocking.
- Added agentic metrics API and Prometheus counters/gauges for roadmap success metrics.

## Phase 2 Control Plane

- Agent key lifecycle:
  - `POST /api/v1/agentic/keys`
  - `GET /api/v1/agentic/keys`
  - `POST /api/v1/agentic/keys/{key_id}/rotate`
  - `POST /api/v1/agentic/revocations`
- Policy and grant lifecycle:
  - `POST /api/v1/agentic/policy-edges`
  - `GET /api/v1/agentic/policy-edges`
  - `POST /api/v1/agentic/grants`
  - `GET /api/v1/agentic/grants`
  - `POST /api/v1/agentic/grants/{execution_id}/revoke`
- Runtime propagation:
  - `GET /api/v1/agentic/config-snapshot`
  - `agentic_security.control_plane_file`
  - `agentic_security.control_plane_reload_seconds`
  - `agentic_security.require_mtls`
  - `agentic_security.agent_cert_fingerprints`
- Observability:
  - `GET /api/v1/agentic/metrics`
  - Prometheus metrics under `/metrics`
- Deployment examples:
  - `nginx/nginx.conf`
  - `deploy/production/Caddyfile.example`
  - `deploy/production/AGENTIC_MTLS.md`

## Success Metrics

- Agent hop policy violation rate (blocked vs attempted)
- Unauthorized MCP server usage (zero target)
- Scope escalation attempts blocked (100% target)
- Mean time to revoke compromised agent identity
