# agentd-secrets -- Secret Access Broker

A Node.js/TypeScript service that brokers access to HashiCorp Vault secrets with human-in-the-loop approval via OIDC + Duo MFA.

## Quickstart

### 1. Initialize configuration

```bash
# Discover Vault config and create agentd-secrets-config.yaml
bin/agentd-secrets-admin.py init \
  --vault-addr https://vault.example.com \
  --vault-token hvs.xxx
```

### 2. Store a secret in Vault

```bash
# Store a secret (JSON from CLI or file)
bin/agentd-secrets-admin.py put-secret logins/google \
  '{"username": "user@example.com", "password": "s3cret"}' \
  --vault-token hvs.xxx

# Verify it's stored
bin/agentd-secrets-admin.py get-secret logins/google --vault-token hvs.xxx

# List all secrets under a path
bin/agentd-secrets-admin.py list-secrets --vault-token hvs.xxx
```

### 3. Configure Vault OIDC auth + policy

```bash
bin/agentd-secrets-admin.py vault-setup \
  --vault-token hvs.xxx \
  --oidc-client-secret '...'
```

This creates/updates the Vault OIDC auth mount config, role, and read policy using OIDC discovery to derive `bound_issuer` and validate the provider.

### 4. Create Kubernetes secret and deploy

```bash
# Create the K8s secret with approver credentials
bin/agentd-secrets-admin.py create-secret \
  --oidc-client-secret '...' \
  --oidc-password '...' \
  --generate-enc-key

# Deploy with Helm
helm install agentd-secrets ./chart \
  --set oidc.issuerURL=https://idp.example.com/realms/myrealm \
  --set oidc.clientID=agentd-secrets \
  --set vault.addr=https://vault.example.com \
  --set vault.oidcMount=agentd-secrets \
  --set vault.oidcRole=agentd-secrets \
  --set vault.kvMount=agentd-secrets \
  --set existingSecret=my-agentd-secrets
```

### 5. Configure the service registry

Add services to `chart/values.yaml` under `serviceRegistry`:

```yaml
serviceRegistry:
  logins:
    vault:
      kv2_path: wyrd/logins
    wrap:
      max_ttl: 300s
      default_ttl: 60s
```

Sub-key addressing lets one entry cover many secrets: requesting `logins/google` reads Vault path `<kvMount>/data/wyrd/logins/google`.

### 6. Verify end-to-end

```bash
# Port-forward to the broker
kubectl port-forward svc/agentd-secrets 8080:8080

# Discover the API
curl http://localhost:8080/

# Test OIDC login (triggers Duo push)
curl -X POST http://localhost:8080/diag/test-login

# Test reading a secret (returns a wrapped token)
curl -X POST http://localhost:8080/diag/test-read \
  -H 'Content-Type: application/json' \
  -d '{"service": "logins/google"}'
```

## How It Works

```
  Bot / Agent              Broker                    Vault             OIDC + Duo
      |                      |                         |                    |
      |-- POST /v1/requests->|                         |                    |
      |<-- 202 {request_id} -|                         |                    |
      |                      |                         |                    |
      |                      |-- auth/oidc/auth_url -->|                    |
      |                      |<-- {auth_url} ----------|                    |
      |                      |                         |                    |
      |                      |-- Playwright login -----|------- login ----->|
      |                      |                         |                    |
      |                      |                         |    Duo push ------>|
      |                      |                         |    <-- approved ---|
      |                      |                         |                    |
      |                      |<-- callback?code&state -|-------- redirect --|
      |                      |-- auth/oidc/callback -->|                    |
      |                      |<-- {client_token} ------|                    |
      |                      |                         |                    |
      |                      |-- GET kv/data/... ----->|                    |
      |                      |   (X-Vault-Wrap-TTL)    |                    |
      |                      |<-- {wrap_token} --------|                    |
      |                      |                         |                    |
      |-- GET /requests/{id}>|                         |                    |
      |<- {APPROVED, token} -|                         |                    |
      |                      |                         |                    |
      |-- POST unwrap ------>|------------------------>|                    |
      |<-- {secret data} ----|-------------------------|                    |
```

1. **Bot requests a secret** -- An automated client sends `POST /v1/requests` with a service name, reason, and identity. No authentication is required from the caller.

2. **Vault OIDC auth URL** -- The broker requests an OIDC auth URL from Vault's OIDC auth method (`POST /v1/auth/{mount}/oidc/auth_url`), providing a `redirect_uri` of `http://localhost:8250/oidc/callback`.

3. **Local callback listener** -- The broker starts an ephemeral HTTP server on `localhost:8250` inside the pod to capture the OIDC callback redirect. This emulates `vault login -method=oidc`.

4. **Headless browser login** -- Playwright opens the Vault-provided auth URL in a headless Chromium browser, fills in the OIDC login form with the dedicated approver credentials, and submits.

5. **Duo MFA push** -- The OIDC provider triggers a Duo push notification to the approver's phone. The human taps "Approve" in Duo Mobile.

6. **Callback capture** -- After Duo approval, the OIDC provider redirects the browser to `http://localhost:8250/oidc/callback?code=...&state=...`. The local listener captures the parameters.

7. **Vault token exchange** -- The broker completes the OIDC callback exchange with Vault. Vault returns a `client_token`.

8. **Vault read with response wrapping** -- Using the Vault token, the broker reads the requested KV v2 secret with `X-Vault-Wrap-TTL` and receives a single-use wrapping token.

9. **Encrypted delivery** -- The wrapping token is encrypted at rest (AES-256-GCM) and stored in memory. The bot polls `GET /v1/requests/{id}` and receives the wrap token once approved.

10. **Secret unwrap** -- The bot sends the wrap token to Vault's unwrap API (`POST /v1/sys/wrapping/unwrap`) to retrieve the actual secret. The wrap token is single-use and time-limited.

The broker **never** sees or returns plaintext secrets -- only Vault wrapping tokens.

## API

### Service Discovery: `GET /`

Returns a self-describing JSON document with all endpoints, schemas, available services, and the Vault address. No authentication required.

### `POST /v1/requests`

Create a new secret access request. No authentication required -- access is controlled by the human approver accepting or rejecting the Duo MFA push.

**Body:**
```json
{
  "service": "logins/google",
  "reason": "Need Google credentials for deployment",
  "requester": "openclaw",
  "wrap_ttl": "5m"
}
```

The `service` field supports sub-key addressing. A service registry entry `logins` with `kv2_path: wyrd/logins` allows requests for `logins/google`, `logins/github`, etc., each reading a separate Vault secret under that path prefix.

**Response (202):**
```json
{
  "request_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "PENDING_APPROVAL"
}
```

### `GET /v1/requests/{id}`

Check request status. Once approved, includes the wrap token.

**Response (200):**
```json
{
  "request_id": "550e8400-e29b-41d4-a716-446655440000",
  "service": "logins/google",
  "requester": "openclaw",
  "status": "APPROVED",
  "created_at": "2026-02-16T03:12:00.000Z",
  "wrap_token": "hvs.CAESI...",
  "wrap_expires_at": "2026-02-16T03:17:00.000Z"
}
```

**Terminal statuses:** `APPROVED`, `DENIED`, `EXPIRED`, `FAILED`

Once you have the `wrap_token`, unwrap the secret from Vault:

```bash
curl -X POST https://vault.example.com/v1/sys/wrapping/unwrap \
  -H "X-Vault-Token: hvs.CAESI..."
```

The wrap token is **single-use** and expires at `wrap_expires_at`.

### `GET /healthz`

Liveness probe. Always returns `200 OK`.

### `GET /readyz`

Readiness probe. Returns `200` if OIDC discovery and Vault `sys/health` are reachable, `503` otherwise.

### Diagnostic Endpoints

These endpoints have no authentication and are intended for operator troubleshooting:

| Method | Path | Description |
|--------|------|-------------|
| POST | `/diag/test-login` | Trigger OIDC login flow to obtain a Vault token |
| GET | `/diag/token-status` | Check cached Vault token validity |
| GET | `/diag/config` | Show non-sensitive config (OIDC URLs, Vault addr, services) |
| POST | `/diag/test-read` | Attempt a Vault KV read for a service (body: `{"service": "logins/google"}`) |

## Service Registry

The service registry is mounted at `/etc/agentd-secrets/config.yaml` via ConfigMap and defines which secrets the broker can access.

```yaml
services:
  logins:
    vault:
      kv2_path: wyrd/logins
    wrap:
      max_ttl: 300s
      default_ttl: 60s
```

### Sub-Key Addressing

A single service entry can cover many individual secrets. The `kv2_path` acts as a prefix:

| Request service | Registry match | Vault KV v2 path read |
|-----------------|---------------|----------------------|
| `logins` | exact match `logins` | `<kvMount>/data/wyrd/logins` |
| `logins/google` | prefix match `logins` + sub-key `google` | `<kvMount>/data/wyrd/logins/google` |
| `logins/github` | prefix match `logins` + sub-key `github` | `<kvMount>/data/wyrd/logins/github` |

The KV mount is always taken from the `vault.kvMount` config (set via `VAULT_KV_MOUNT` env var or Helm `vault.kvMount`).

### Optional Fields

- `vault.kv2_mount` -- Per-service KV mount override. Optional; defaults to `vault.kvMount` from the global config. Usually omitted since the mount is already defined globally.
- `authz` -- Reserved for future per-service authorization. Not currently enforced; approval is via Duo MFA push.

## Configuration Reference

### Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `OIDC_ISSUER_URL` | Yes | -- | OIDC realm issuer URL |
| `OIDC_CLIENT_ID` | Yes | -- | Broker's OIDC client ID |
| `VAULT_ADDR` | Yes | -- | Vault server address |
| `VAULT_OIDC_MOUNT` | No | `oidc` | Vault OIDC auth method mount path |
| `VAULT_OIDC_ROLE` | No | `agentd-secrets` | Vault OIDC auth role |
| `VAULT_KV_MOUNT` | No | `secret` | Vault KV v2 secrets engine mount |
| `VAULT_WRAP_TTL` | No | `300s` | Default Vault response wrap TTL |
| `OIDC_LOCAL_LISTEN_HOST` | No | `127.0.0.1` | Callback listener bind address |
| `OIDC_LOCAL_LISTEN_PORT` | No | `8250` | Callback listener port |
| `OIDC_LOCAL_REDIRECT_URI` | No | `http://localhost:8250/oidc/callback` | OIDC redirect URI |
| `WRAPTOKEN_ENC_KEY` | Yes | -- | 64 hex chars (32 bytes) for AES-256-GCM encryption |
| `BROKER_LISTEN_ADDR` | No | `:8080` | Listen address |
| `BROKER_CONFIG_PATH` | No | `/etc/agentd-secrets/config.yaml` | Path to service registry |
| `OIDC_USERNAME` | Yes | -- | OIDC user for headless login |
| `OIDC_PASSWORD` | Yes | -- | Password for the approver user |
| `OIDC_LOGIN_TIMEOUT` | No | `2m` | Timeout for OIDC login page |
| `OIDC_DUO_TIMEOUT` | No | `5m` | Timeout waiting for Duo push approval |
| `PLAYWRIGHT_HEADLESS` | No | `true` | Run Chromium headless |
| `PLAYWRIGHT_BROWSER` | No | `chromium` | Browser engine |
| `PLAYWRIGHT_BROWSERS_PATH` | No | `/usr/local/lib/pw-browsers` | Path to Playwright browser binaries |
| `LOG_LEVEL` | No | `info` | Log level (debug, info, warn, error) |

## Admin CLI

The `bin/agentd-secrets-admin.py` script provides a unified CLI for setup and operations:

### Setup Commands

```bash
# Discover Vault and create config file
bin/agentd-secrets-admin.py init --vault-addr https://vault.example.com --vault-token hvs.xxx

# Configure build settings (registry, image, tag)
bin/agentd-secrets-admin.py configure

# Create Kubernetes secret
bin/agentd-secrets-admin.py create-secret \
  --oidc-client-secret '...' \
  --oidc-password '...' \
  --generate-enc-key

# Configure Vault OIDC auth mount, role, and policy
bin/agentd-secrets-admin.py vault-setup \
  --vault-token hvs.xxx \
  --oidc-client-secret '...'

# Generate Helm values from config
bin/agentd-secrets-admin.py create-values
```

### Secret Management

```bash
# Store a secret (JSON string or @file)
bin/agentd-secrets-admin.py put-secret logins/google \
  '{"username": "user@example.com", "password": "s3cret"}' \
  --vault-token hvs.xxx

# Read a specific secret
bin/agentd-secrets-admin.py get-secret logins/google --vault-token hvs.xxx

# List all secrets (no name argument)
bin/agentd-secrets-admin.py get-secret --vault-token hvs.xxx

# List secret names under a path
bin/agentd-secrets-admin.py list-secrets --vault-token hvs.xxx
```

### Sync (Declarative State Management)

The `sync` subcommand reads the config YAML and ensures Vault policies, OIDC auth config, and roles match the desired state. It uses OIDC discovery to derive `bound_issuer`, `jwks_uri`, and other provider metadata automatically.

```bash
# Apply changes
bin/agentd-secrets-admin.py sync --vault-token $VAULT_TOKEN

# Dry run -- show plan without applying (exit 2 on drift)
bin/agentd-secrets-admin.py sync --vault-token $VAULT_TOKEN --dry-run
```

Sync operates in two modes:
- **Single-profile mode** (no `bots` section): Creates one policy + one OIDC role from `vault.policy_name` and `vault.oidc_role`.
- **Multi-bot mode** (`bots` list present): Creates per-bot policies with isolated secret paths and a shared policy for common secrets.

See `bin/agentd-secrets-admin.py --help` for full usage.

### Admin Config File (`agentd-secrets-config.yaml`)

```yaml
vault:
  addr: https://vault.example.com
  oidc_mount: agentd-secrets
  oidc_role: agentd-secrets
  policy_name: agentd-secrets-read
  kv_mount: agentd-secrets
  secret_prefix: wyrd
  wrap_ttl: 300s
  role:
    allowed_redirect_uris: http://localhost:8250/oidc/callback
    user_claim: preferred_username
    bound_claim_key: preferred_username
    bound_claim_value: approver-username
    token_ttl: 15m

oidc:
  issuer_url: https://idp.example.com/realms/myrealm
  client_id: agentd-secrets
  client_password: ""
  bound_issuer: ""            # derived from OIDC discovery if empty
  response_types: code
  supported_algs: RS256
  scopes: openid,profile,email
  username: approver
  password: ""
  callback_listen_host: "0.0.0.0"
  callback_listen_port: 8250
  callback_redirect_uri: http://localhost:8250/oidc/callback

kubernetes:
  namespace: default
  secret_name: my-agentd-secrets

playwright:
  headless: true
  browser: chromium
  login_timeout: 2m
  duo_timeout: 5m

target:
  registry: myregistry
  image: agentd-secrets
  tag: latest
```

### Multi-Bot Config Example

```yaml
vault:
  # ... same as above ...
  policies:
    shared_policy_name: agentd-secrets-shared-read
    bot_policy_prefix: agentd-secrets-bot-

bots:
  - name: openclaw
    approver_username: openclaw-approver
    approver_email: openclaw@example.com
  - name: roadrunner
    approver_username: roadrunner-approver

# ...
```

#### Per-Bot Isolation

Sync enforces strict secret isolation between bots:

| Path | Access | Capabilities |
|---|---|---|
| `<mount>/data/<prefix>/shared/*` | All bots | read |
| `<mount>/metadata/<prefix>/shared/*` | All bots | list |
| `<mount>/data/<prefix>/bots/<bot>/*` | Only that bot | read |
| `<mount>/metadata/<prefix>/bots/<bot>/*` | Only that bot | list |

Each bot authenticates via its own OIDC role bound to a unique OIDC user. Vault denies any path not explicitly granted by the attached policies.

#### Required Vault Permissions for Sync

The admin token used with `--vault-token` needs:

- `sys/auth` -- list and enable auth methods
- `sys/mounts` -- list secret engines
- `sys/policies/acl/*` -- read and write policies
- `auth/<oidc_mount>/config` -- read and write OIDC config
- `auth/<oidc_mount>/role/*` -- read and write OIDC roles

## Prerequisites

### Vault OIDC Auth Method

Use `vault-setup` or `sync` to configure automatically, or manually:

```bash
vault write auth/oidc/role/agentd-secrets \
  bound_audiences="agentd-secrets" \
  allowed_redirect_uris="http://localhost:8250/oidc/callback" \
  user_claim="preferred_username" \
  role_type="oidc" \
  policies="agentd-secrets-read" \
  oidc_scopes="openid,profile,email" \
  token_ttl="15m"
```

The `vault-setup` command fetches OIDC discovery metadata to populate `bound_issuer`, `oidc_response_types`, and `jwt_supported_algs` automatically.

### OIDC Client

The OIDC client must have `http://localhost:8250/oidc/callback` as a valid redirect URI. Since the callback is on localhost inside the pod, no public ingress is needed.

### Vault KV Policy

The policy attached to the OIDC role must grant read access to the KV v2 paths:

```hcl
path "<kv_mount>/data/<secret_prefix>/*" {
  capabilities = ["read"]
}

path "<kv_mount>/metadata/<secret_prefix>/*" {
  capabilities = ["list"]
}
```

## Security Notes

- **No plaintext secrets** -- The broker never returns Vault secret data. Only single-use Vault wrapping tokens are returned.
- **Localhost callback** -- The OIDC callback listener runs inside the pod. No public callback endpoint is exposed.
- **Token caching with mutex** -- Concurrent requests share a single Vault token. Only one OIDC login happens at a time; subsequent requests reuse the cached token until it expires (at 80% of lease duration).
- **Wrap tokens encrypted at rest** -- AES-256-GCM with a random 12-byte nonce. Key provided via `WRAPTOKEN_ENC_KEY`.
- **Network-level access control** -- The broker has no caller authentication. Access is restricted by Kubernetes network policy (ClusterIP service) and authorized by the human approver via Duo MFA push.
- **Rate limiting** -- `POST /v1/requests` is rate-limited (30 req/min per IP).
- **Request IDs** -- UUIDv4, cryptographically random and unguessable.
- **Wrap TTL capping** -- Requested TTLs are capped to the service's `max_ttl`.
- **Request expiry** -- Pending requests expire after 15 minutes. Old requests are cleaned up after 1 hour.
- **No sensitive data in logs** -- Passwords, tokens, and secrets are never logged.
- **Headless browser isolation** -- Each login gets a fresh browser context, closed after use.
- **Non-root container** -- Runs as a dedicated `agentd` user (UID 1500) with read-only root filesystem.

### Risk: Storing Approver Credentials

The broker stores a real OIDC user's password (`OIDC_PASSWORD`) in a Kubernetes Secret. Recommendations:

- Use a **dedicated service account user** with minimal permissions (only the ability to authenticate and trigger Duo).
- Set **short session timeouts** for this user in the OIDC provider.
- Restrict the Kubernetes Secret with RBAC so only the broker pod can read it.
- Rotate the password regularly.
- Consider using Vault itself to store the password and bootstrapping via a different auth method.

## Development

```bash
# Install dependencies
npm install

# Build
npm run build

# Run tests
npm test

# Run only unit tests
npm run test:unit

# Run only integration tests
npm run test:integration

# Lint
npm run lint

# Format
npm run format
```

### Sync Tests (Python)

```bash
pip install -r requirements.txt
pytest tests/test_sync.py -v
```

## Docker

```bash
docker build -t agentd-secrets:latest .
```

The container runs as the `agentd` user (UID/GID 1500) with Playwright browsers installed at `/usr/local/lib/pw-browsers`. A writable home directory is provided via an emptyDir volume at `/home/agentd`.

## Deployment (Helm)

```bash
helm install agentd-secrets ./chart \
  --set oidc.issuerURL=https://idp.example.com/realms/myrealm \
  --set oidc.clientID=agentd-secrets \
  --set vault.addr=https://vault.example.com \
  --set vault.oidcMount=agentd-secrets \
  --set vault.oidcRole=agentd-secrets \
  --set vault.kvMount=agentd-secrets \
  --set existingSecret=my-agentd-secrets
```

## Troubleshooting

### "Callback never hit" / OIDC callback timeout

- **OIDC redirect URI**: Ensure the OIDC provider client has `http://localhost:8250/oidc/callback` in its valid redirect URIs.
- **Vault role redirect URI**: Ensure the Vault OIDC role has the same URI in `allowed_redirect_uris`.
- **Port conflict**: Verify nothing else in the pod is listening on port 8250.

### "Permission denied" / 403 from Vault

- The Vault OIDC role's policies must grant read access to the requested KV v2 paths.
- Verify the Vault token has the expected policies: `vault token lookup`.

### "Duo prompt loops" or never completes

- The approver user must be enrolled in Duo with a valid device.
- Check Duo admin console for failed push attempts.
- Increase `OIDC_DUO_TIMEOUT` if the user is slow to respond.
- The Playwright driver handles Duo "Trust this browser" interstitials automatically.

### "Invalid token" / 403 on Vault KV read

- The cached Vault token may have expired. The broker re-authenticates when the token reaches 80% of its lease duration.
- Check Vault audit logs for token validation errors.
- Ensure the Vault OIDC role's `token_ttl` is long enough for the operations.

### 404 on secret read

- Verify the service registry `kv2_path` matches the actual Vault KV path.
- With sub-key addressing, `logins/google` reads `<kv2_path>/google`. Ensure the secret exists at that exact path.
- Use `bin/agentd-secrets-admin.py get-secret <path>` to verify the secret exists.

### Token appears valid but gets 403

- The Vault token TTL may be shorter than the cached `leaseDuration` suggests. The broker considers a token valid for 80% of its reported lease duration. If the actual Vault-side TTL is shorter (e.g. 60s vs 15m), the broker may try to reuse an expired token.

## Operational Notes

- **Single replica assumption** -- The in-memory request store means only one replica should run. If scaling beyond one replica, use sticky sessions so the bot's GET poll hits the same pod that processed its POST.
- **Duo timeout** -- The `OIDC_DUO_TIMEOUT` (default 5m) determines how long the broker waits for the human to approve the Duo push.
- **Browser resource usage** -- Each pending login spawns a headless Chromium instance. Monitor memory usage and set appropriate resource limits.
- **Request cleanup** -- Expired and completed requests are automatically cleaned up after 1 hour.
- **Token reuse** -- The broker caches the Vault token and reuses it for multiple requests. A login mutex ensures only one OIDC flow runs at a time.
