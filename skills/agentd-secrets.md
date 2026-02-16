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
