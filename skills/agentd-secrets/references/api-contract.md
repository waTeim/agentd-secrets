# agentd-secrets API Contract

## Discovery

GET http://<BROKER_HOST>/

Response:
```json
{
  "service": "agentd-secrets",
  "version": "0.1.0",
  "endpoints": {
    "POST /v1/requests": {
      "description": "Request access to a secret. Triggers Duo MFA push.",
      "body": {
        "service": "string (required) — e.g. logins/google",
        "reason": "string (required)",
        "requester": "string (required)",
        "wrap_ttl": "string (optional) — e.g. 5m, 300s"
      },
      "response": "202 { request_id, status }"
    },
    "GET /v1/requests/:id": {
      "description": "Poll request status.",
      "response": "200 { request_id, service, requester, status, created_at, wrap_token?, wrap_expires_at?, failure_reason? }",
      "statuses": ["PENDING_APPROVAL", "APPROVED", "DENIED", "EXPIRED", "FAILED"]
    },
    "GET /v1/services": {
      "description": "List all services including Vault sub-keys.",
      "response": "200 { services: string[] }"
    },
    "GET /healthz": { "description": "Liveness check" },
    "GET /readyz": { "description": "Readiness check" }
  },
  "services": ["logins"],
  "vault_addr": "https://vault.wat.im"
}
```

## List Services

GET http://<BROKER_HOST>/v1/services

Returns full sub-key paths discovered from Vault:
```json
{ "services": ["logins/github", "logins/google"] }
```

Triggers OIDC/Duo login if no valid Vault token is cached.

## Request a Secret

POST http://<BROKER_HOST>/v1/requests

```json
{
  "service": "logins/google",
  "reason": "Need credentials for deployment",
  "requester": "openclaw",
  "wrap_ttl": "60s"
}
```

Response (202):
```json
{ "request_id": "550e8400-...", "status": "PENDING_APPROVAL" }
```

## Poll Status

GET http://<BROKER_HOST>/v1/requests/:id

Poll every 3-5s. Request expires after 15 minutes.

When approved:
```json
{
  "request_id": "550e8400-...",
  "status": "APPROVED",
  "wrap_token": "hvs.CAESIxyz...",
  "wrap_expires_at": "2026-02-16T03:17:00.000Z"
}
```

Terminal failure statuses: DENIED, FAILED, EXPIRED (check `failure_reason`).

## Unwrap

POST <VAULT_ADDR>/v1/sys/wrapping/unwrap
Header: X-Vault-Token: <wrap_token>

Secret is in `.data.data` (Vault KV v2 nesting):
```json
{
  "data": {
    "data": {
      "username": "user@example.com",
      "password": "secret123"
    }
  }
}
```

wrap_token is single-use. Unwrap immediately.

## Rate Limits

- POST /v1/requests: 30/minute per IP (broker-enforced)
- Completed requests garbage-collected after 1 hour
