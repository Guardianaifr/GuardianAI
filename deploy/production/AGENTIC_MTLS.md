# Agentic mTLS Binding

GuardianAI Phase 2 supports app-level binding between signed agent identity and
reverse-proxy-verified client certificates.

## Flow

1. Terminate TLS at Nginx, Caddy, Cloudflare, or another trusted edge.
2. Require and verify client certificates against your agent client CA.
3. Forward verified certificate metadata to Guardian:
   - `X-Guardian-mTLS-Verified`
   - `X-Guardian-mTLS-Fingerprint`
   - `X-Guardian-mTLS-Subject`
4. Enable runtime binding:

```yaml
agentic_security:
  enabled: true
  require_agent_id: true
  require_agent_attestation: true
  require_mtls: true
  mtls_verified_header: "X-Guardian-mTLS-Verified"
  mtls_fingerprint_header: "X-Guardian-mTLS-Fingerprint"
  mtls_subject_header: "X-Guardian-mTLS-Subject"
  mtls_verified_value: "SUCCESS"
```

## Control Plane

Register an agent key with allowed certificate fingerprints:

```bash
curl -u admin:admin-pass \
  -H "Content-Type: application/json" \
  -d '{"agent_id":"agent-a","key_id":"key-1","cert_fingerprints":["AA:BB:CC"]}' \
  http://127.0.0.1:8001/api/v1/agentic/keys
```

Export the runtime snapshot:

```bash
curl -u admin:admin-pass \
  http://127.0.0.1:8001/api/v1/agentic/config-snapshot \
  > artifacts/control/agentic_control_plane.json
```

Point the proxy at the snapshot:

```yaml
agentic_security:
  control_plane_file: "artifacts/control/agentic_control_plane.json"
  control_plane_reload_seconds: 5
```

## Header Trust

Only accept `X-Guardian-mTLS-*` headers from your trusted reverse proxy. Strip
incoming client-supplied copies at the edge before setting the verified values.
