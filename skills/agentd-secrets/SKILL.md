# Skill: agentd-secrets -- Obtain Secrets from Vault

Use this skill when you need to retrieve a secret (credentials, API keys, passwords, tokens) from the organization's Vault instance. The agentd-secrets broker handles Vault authentication and MFA approval on your behalf. No authentication is required from the caller -- access control is enforced via Duo MFA push to a human approver.

## Discovery

To discover what the broker offers, fetch its root endpoint:

```bash
curl -s http://agentd-secrets:8080/
```

This returns the full API schema, available services, and the Vault address for unwrapping.

## Step-by-Step: Obtain a Secret

### 1. Request the secret

```bash
curl -s -X POST http://agentd-secrets:8080/v1/requests \
  -H "Content-Type: application/json" \
  -d '{
    "service": "logins/google",
    "reason": "Need Google credentials for deployment task",
    "requester": "openclaw"
  }'
```

Response (202):
```json
{
  "request_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "PENDING_APPROVAL"
}
```

The `service` field supports sub-key addressing: `logins/google`, `logins/github`, etc. map to individual secrets under the `logins` service prefix.

### 2. Poll for approval

The request triggers a Duo MFA push to the human approver. Poll until the status changes from `PENDING_APPROVAL`:

```bash
curl -s http://agentd-secrets:8080/v1/requests/$REQUEST_ID
```

Poll every 3-5 seconds. Typical approval takes 5-30 seconds. The request expires after 15 minutes if not approved.

Response when approved:
```json
{
  "request_id": "550e8400-e29b-41d4-a716-446655440000",
  "service": "logins/google",
  "requester": "openclaw",
  "status": "APPROVED",
  "created_at": "2026-02-16T03:12:00.000Z",
  "wrap_token": "hvs.CAESIxyz...",
  "wrap_expires_at": "2026-02-16T03:17:00.000Z"
}
```

Other terminal statuses:
- `DENIED` -- MFA push was rejected. `failure_reason` field explains why.
- `FAILED` -- Vault error. `failure_reason` field explains why.
- `EXPIRED` -- No approval within 15 minutes.

### 3. Unwrap the secret from Vault

The `wrap_token` is a single-use Vault response-wrapping token. Get the Vault address from the discovery endpoint (`GET /`), then unwrap:

```bash
curl -s -X POST $VAULT_ADDR/v1/sys/wrapping/unwrap \
  -H "X-Vault-Token: $WRAP_TOKEN"
```

Response:
```json
{
  "data": {
    "data": {
      "username": "user@example.com",
      "password": "secret123"
    },
    "metadata": { ... }
  }
}
```

The actual secret is in `.data.data` (Vault KV v2 nesting). The wrap token can only be used **once** and expires at `wrap_expires_at`.

## Important Notes

- **No authentication required**: The broker does not require any tokens or credentials from the caller. Access is controlled by the human approver accepting or rejecting the Duo MFA push.
- **Single-use tokens**: Each `wrap_token` can only be unwrapped once. If you need the secret again, create a new request.
- **TTL**: The wrap token has a limited lifetime (default 60s-300s depending on the service). Unwrap it promptly.
- **Vault address**: Get the Vault address from the broker's discovery endpoint (`GET /`).
- **Available services**: Check `GET /` to see which services are registered. Use sub-key addressing (`service/subkey`) to access individual secrets under a prefix.
- **Rate limiting**: POST requests are limited to 30/minute per IP.
- **Request garbage collection**: Completed requests are removed from memory after 1 hour. Poll promptly.

## Quick Reference

| Action | Method | Path | Auth |
|--------|--------|------|------|
| Discover API | GET | `/` | None |
| Request secret | POST | `/v1/requests` | None |
| Poll status | GET | `/v1/requests/:id` | None |
| Health check | GET | `/healthz` | None |
| Readiness | GET | `/readyz` | None |
| Unwrap secret | POST | `<vault>/v1/sys/wrapping/unwrap` | X-Vault-Token |

## Auto-Request Helper

Instead of composing individual curl commands, use the helper script to request, poll, and unwrap in a single call:

```bash
python3 skills/agentd-secrets/scripts/fetch.py <service> <reason> [requester] [wrap_ttl]
```

Example:

```bash
python3 skills/agentd-secrets/scripts/fetch.py logins/google "Need credentials for deployment"
```

The script:
1. Discovers the broker and validates the service exists
2. Creates the request (triggers Duo push)
3. Polls until approved, denied, or timed out
4. Unwraps the secret from Vault
5. Prints the secret JSON (`.data.data`) to stdout
6. Appends an audit entry to the audit log

On unwrap failure (expired token, HTTP 400), retries the full flow up to `max_retries` times with 5s backoff. Secrets are **never** written to files -- stdout only. No third-party dependencies -- stdlib only.

### Environment Variable Overrides

| Variable | Default | Description |
|----------|---------|-------------|
| `AGENTD_BROKER_URL` | `http://wyrd-agentd-secrets:8080` | Broker base URL |
| `AGENTD_POLL_TIMEOUT` | `900` (15m) | Max seconds to wait for approval |
| `AGENTD_POLL_INTERVAL` | `3` | Seconds between poll requests |
| `AGENTD_MAX_RETRIES` | `2` | Full-flow retries on unwrap failure |
| `AGENTD_AUDIT_LOG` | `/tmp/agentd-secrets-audit.log` | Audit log path |

### Example Output

```json
{
  "username": "user@example.com",
  "password": "secret123"
}
```

## Auto-Infer Mode

When enabled, the agent can map natural language intent to service names without the user specifying the exact service path. The phrase-to-service mapping is maintained in [`references/inference-map.yaml`](references/inference-map.yaml) and enabled via `config.yaml`:

```yaml
enable_auto_infer: true   # default: false
```

Example mappings (see `references/inference-map.yaml` for the full list):

```yaml
"use your google account": "logins/google"
"deploy using github": "logins/github"
"github credentials": "logins/github"
```

**Disabled by default.** To enable, set `enable_auto_infer: true` in `config.yaml`. The agent will match user intent against the inference map keys and resolve to the corresponding service name.

To extend, add new phrase-to-service mappings in `references/inference-map.yaml`. Phrases are matched as substrings (case-insensitive). The agent should confirm the inferred service with the user before making the request on the first autonomous use.

## Behavior & Consent

- **Ephemeral storage**: Secrets are printed to stdout and never persisted to disk. The `storage: ephemeral` config enforces this policy.
- **Confirmation before first use**: On the first autonomous secret request in a session, the agent should confirm with the user: "I can request secrets from Vault on your behalf -- a Duo push will be sent for approval. Proceed?"
- **Duo approval always required**: No secret can be retrieved without a human approving the Duo MFA push. The broker enforces this server-side; the skill cannot bypass it.
- **No silent requests**: The agent must always state which service it is requesting and why before calling the helper.

## Audit & Logging

Every invocation of `scripts/fetch.py` appends a line to the audit log (default `/tmp/agentd-secrets-audit.log`):

```
2026-02-16T03:12:45Z OK service=logins/google request_id=550e8400-... requester=agent
2026-02-16T03:15:00Z DENIED service=logins/github request_id=661f9500-... reason="MFA rejected"
2026-02-16T03:20:00Z FAIL service=logins/google request_id=772a0600-... error="Poll timeout after 900s"
```

Each entry includes: timestamp (UTC), outcome (`OK`, `DENIED`, `EXPIRED`, `FAIL`, `UNWRAP_FAIL`, `TIMEOUT`), service, request_id, and relevant context.

The broker also logs all requests server-side with full details (requester, service, timestamps, approval status).

To view the audit log:

```bash
cat /tmp/agentd-secrets-audit.log
```

## Smoke Test

Run the end-to-end smoke test (requires a running broker and Duo approval):

```bash
python3 skills/agentd-secrets/scripts/smoke-test.py
```

Verifies: exit code, valid JSON output, audit log appended. Prints pass/fail summary.

## Safe Defaults

| Setting | Default | Notes |
|---------|---------|-------|
| `default_wrap_ttl` | `1m` | Short TTL to minimize exposure window |
| `max_retries` | `2` | Retry full flow on unwrap failure only |
| `poll_timeout` | `900s` (15m) | Matches broker-side request expiry |
| `poll_interval` | `3s` | Stays well under 30 req/min rate limit |
| `storage` | `ephemeral` | Secrets printed to stdout, never written to files |
| `auto_infer` | `disabled` | Must be explicitly enabled |
| Rate limit | 30 POST/min | Enforced broker-side per IP |

## Skill Layout

```
skills/agentd-secrets/
  SKILL.md              # this file
  config.yaml           # skill configuration
  scripts/
    fetch.py            # single-command secret retrieval
    smoke-test.py       # end-to-end smoke test
  references/
    inference-map.yaml  # intent-to-service mapping for auto-infer
```
