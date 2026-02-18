---
name: agentd-secrets
description: >
  Retrieve secrets from HashiCorp Vault via a broker with human-in-the-loop Duo
  MFA approval. Use when the agent needs credentials, API keys, passwords, or
  tokens from the organization's Vault instance. No caller authentication
  required — access control is enforced by the human approver accepting or
  rejecting the Duo push. Supports service discovery, sub-key addressing
  (e.g. logins/google), and a single-command fetch script.
---

# agentd-secrets

Obtain Vault-protected secrets through a broker that handles OIDC login and Duo MFA approval.

## Workflow

### 1. Confirm broker host

Before any request, confirm BROKER_HOST with the user. Default: `wyrd-agentd-secrets:8080`.

### 2. Discover available services

```bash
curl -sS http://<BROKER_HOST>/v1/services
```

Returns full sub-key paths (e.g. `["logins/github", "logins/google"]`). Triggers Duo login if no cached token.

For broker metadata and vault_addr, use `GET /`. See [references/api-contract.md](references/api-contract.md) for full API details.

### 3. Request, poll, unwrap

Use `scripts/fetch.py` to run the entire flow in one command:

```bash
python3 scripts/fetch.py <service> <reason> [requester] [wrap_ttl]
```

Example:

```bash
python3 scripts/fetch.py logins/google "Need credentials for deployment"
```

The script discovers the broker, creates the request (triggers Duo push), polls until approved, unwraps from Vault, and prints the secret JSON to stdout. On unwrap failure it retries the full flow with backoff. Requires Python 3.8+, stdlib only.

For manual curl-based flow or response format details, see [references/api-contract.md](references/api-contract.md).

## Policy

- **Confirm before acting.** Before the first secret request in a session, confirm with the user that they authorize the agent to trigger a Duo push.
- **State the service and reason.** Always announce which service is being requested and why before calling fetch.py.
- **Duo approval always required.** No secret can be retrieved without a human approving the MFA push. The broker enforces this server-side.
- **Ephemeral only.** Never write secrets to files. Print to stdout or use in-memory only.
- **Redact in chat.** Report key names present in the secret, not values, unless the user explicitly requests otherwise.

## Configuration

Runtime defaults are in `config.yaml` at the skill root. Environment variables override config when using fetch.py. See [references/configuration.md](references/configuration.md) for all options.

## Auto-Infer (optional)

When `enable_auto_infer: true` in config.yaml, the agent maps natural language intent to service names using [references/inference-map.yaml](references/inference-map.yaml). Disabled by default. Confirm the inferred service with the user before requesting.

## Testing

Run the end-to-end smoke test (requires a running broker and Duo approval):

```bash
python3 scripts/smoke-test.py
```

Verifies: exit code, valid JSON output, audit log entry appended.
