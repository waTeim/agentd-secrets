# x-pass — Secret Access Broker

A Node.js/TypeScript service that brokers access to HashiCorp Vault secrets with human-in-the-loop approval via Keycloak + Duo MFA.

## How It Works

```
Bot (CI/CD)                  x-pass Broker                   Vault                 Keycloak + Duo
    |                             |                            |                         |
    |-- POST /v1/requests ------->|                            |                         |
    |<-- 202 {request_id} --------|                            |                         |
    |                             |-- POST auth/oidc/auth_url ->|                         |
    |                             |<-- {auth_url} --------------|                         |
    |                             |-- Start localhost:8250 --->||                         |
    |                             |-- Playwright opens auth_url ----------------------->  |
    |                             |                            |   Login + Duo push  ---> |
    |                             |                            |   <--- Duo approved       |
    |                             |<-- GET localhost:8250/oidc/callback?code=...&state=... |
    |                             |-- GET auth/oidc/callback -->|                         |
    |                             |<-- {client_token} ---------|                         |
    |                             |-- GET kv/data/... -------->|                         |
    |                             |   (X-Vault-Wrap-TTL)       |                         |
    |                             |<-- {wrap_token} -----------|                         |
    |-- GET /v1/requests/{id} --->|                            |                         |
    |<-- {status:APPROVED, wrap_token} --|                     |                         |
```

1. **Bot requests a secret** -- An automated client sends `POST /v1/requests` with a service name, reason, and identity. The bot authenticates with a Keycloak-issued JWT (Bearer token).

2. **Vault OIDC auth URL** -- The broker requests an OIDC auth URL from Vault's OIDC auth method (`POST /v1/auth/{mount}/oidc/auth_url`), providing a `redirect_uri` of `http://localhost:8250/oidc/callback`.

3. **Local callback listener** -- The broker starts an ephemeral HTTP server on `127.0.0.1:8250` inside the pod to capture the OIDC callback redirect. This emulates `vault login -method=oidc`.

4. **Headless browser login** -- Playwright opens the Vault-provided auth URL in a headless Chromium browser, fills in the Keycloak login form with the dedicated approver credentials, and submits.

5. **Duo MFA push** -- Keycloak triggers a Duo push notification to the approver's phone. The human taps "Approve" in Duo Mobile.

6. **Callback capture** -- After Duo approval, Keycloak redirects the browser to `http://localhost:8250/oidc/callback?code=...&state=...`. The local listener captures the parameters.

7. **Vault token exchange** -- The broker completes the OIDC callback exchange with Vault (`GET /v1/auth/{mount}/oidc/callback?state=...&code=...&client_nonce=...`). Vault returns a `client_token`.

8. **Vault read with response wrapping** -- Using the Vault token, the broker reads the requested KV v2 secret with `X-Vault-Wrap-TTL` and receives a single-use wrapping token.

9. **Encrypted delivery** -- The wrapping token is encrypted at rest (AES-256-GCM) and stored in memory. The bot polls `GET /v1/requests/{id}` and receives the wrap token once approved.

The broker **never** sees or returns plaintext secrets -- only Vault wrapping tokens.

## API

### `POST /v1/requests`

Create a new secret access request.

**Headers:** `Authorization: Bearer <JWT>`

**Body:**
```json
{
  "service": "payroll-db",
  "reason": "Automated deployment rotation",
  "requester": "ci-bot-prod",
  "wrap_ttl": "5m"
}
```

**Response (202):**
```json
{
  "request_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "PENDING_APPROVAL"
}
```

### `GET /v1/requests/{id}`

Check request status. Once approved, includes the wrap token.

**Headers:** `Authorization: Bearer <JWT>`

**Response (200):**
```json
{
  "request_id": "550e8400-e29b-41d4-a716-446655440000",
  "service": "payroll-db",
  "requester": "ci-bot-prod",
  "status": "APPROVED",
  "created_at": "2025-01-15T10:30:00.000Z",
  "wrap_token": "hvs.CAESI...",
  "wrap_expires_at": "2025-01-15T10:35:00.000Z"
}
```

**Terminal statuses:** `APPROVED`, `DENIED`, `EXPIRED`, `FAILED`

### `GET /healthz`

Liveness probe. Always returns `200 OK`.

### `GET /readyz`

Readiness probe. Returns `200` if Keycloak OIDC discovery and Vault `sys/health` are reachable, `503` otherwise.

## Configuration Reference

### Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `KEYCLOAK_ISSUER_URL` | Yes | -- | Keycloak realm issuer URL |
| `KEYCLOAK_REALM` | No | `""` | Keycloak realm name |
| `KEYCLOAK_CLIENT_ID` | Yes | -- | Broker's Keycloak client ID |
| `KEYCLOAK_CLIENT_SECRET` | Yes | -- | Broker's Keycloak client secret |
| `KEYCLOAK_AUDIENCE` | No | `""` | Expected JWT audience claim |
| `VAULT_ADDR` | Yes | -- | Vault server address |
| `VAULT_OIDC_MOUNT` | No | `oidc` | Vault OIDC auth method mount path |
| `VAULT_OIDC_ROLE` | No | `wyrd-x-pass` | Vault OIDC auth role |
| `VAULT_KV_MOUNT` | No | `secret` | Vault KV v2 secrets engine mount |
| `VAULT_WRAP_TTL` | No | `300s` | Default Vault response wrap TTL |
| `OIDC_LOCAL_LISTEN_HOST` | No | `127.0.0.1` | Callback listener bind address |
| `OIDC_LOCAL_LISTEN_PORT` | No | `8250` | Callback listener port |
| `OIDC_LOCAL_REDIRECT_URI` | No | `http://localhost:8250/oidc/callback` | OIDC redirect URI |
| `WRAPTOKEN_ENC_KEY` | Yes | -- | 64 hex chars (32 bytes) for AES-256-GCM encryption |
| `BROKER_LISTEN_ADDR` | No | `:8080` | Listen address |
| `BROKER_CONFIG_PATH` | No | `/etc/x-pass/config.yaml` | Path to service registry |
| `KEYCLOAK_USERNAME` | Yes | -- | Keycloak user for headless login |
| `KEYCLOAK_PASSWORD` | Yes | -- | Password for the approver user |
| `KC_LOGIN_TIMEOUT` | No | `2m` | Timeout for Keycloak login page |
| `KC_DUO_TIMEOUT` | No | `5m` | Timeout waiting for Duo push approval |
| `PLAYWRIGHT_HEADLESS` | No | `true` | Run Chromium headless |
| `PLAYWRIGHT_BROWSER` | No | `chromium` | Browser engine |
| `LOG_LEVEL` | No | `info` | Log level (debug, info, warn, error) |

### Service Registry (`config.yaml`)

Mounted at `/etc/x-pass/config.yaml` via ConfigMap:

```yaml
services:
  payroll-db:
    vault:
      kv2_mount: "secret"
      kv2_path: "prod/payroll/db"
    authz:
      keycloak:
        resource_id: "vault:payroll-db"
        scope: "read"
    wrap:
      max_ttl: "10m"
      default_ttl: "5m"
```

The `authz` block is retained for backward compatibility but is not used for gating in this version; approval is via Duo push.

## Prerequisites

### Vault OIDC Auth Method

The Vault OIDC auth method must be enabled and configured with Keycloak as the identity provider. The Vault role must include `http://localhost:8250/oidc/callback` in its `allowed_redirect_uris`:

```bash
vault write auth/oidc/role/wyrd-x-pass \
  bound_audiences="x-pass" \
  allowed_redirect_uris="http://localhost:8250/oidc/callback" \
  user_claim="preferred_username" \
  role_type="oidc" \
  policies="x-pass-read" \
  token_ttl="15m"
```

### Keycloak Client

The Keycloak OIDC client (`wyrd-x-pass` or whatever `KEYCLOAK_CLIENT_ID` is set to) must have `http://localhost:8250/oidc/callback` as a valid redirect URI. Since the callback is on localhost inside the pod, no public ingress is needed.

### Vault KV Policy

The Vault policy attached to the OIDC role must grant read access to the KV v2 paths referenced in the service registry:

```hcl
path "secret/data/prod/payroll/*" {
  capabilities = ["read"]
}
```

## Security Notes

- **No plaintext secrets** -- The broker never returns Vault secret data. Only single-use Vault wrapping tokens are returned.
- **Localhost callback** -- The OIDC callback listener runs on `127.0.0.1` inside the pod. No public callback endpoint is exposed.
- **Token caching with mutex** -- Concurrent requests share a single Vault token (Option A: serialized logins). Only one OIDC login happens at a time; subsequent requests reuse the cached token until it expires.
- **Wrap tokens encrypted at rest** -- AES-256-GCM with a random 12-byte nonce prepended to ciphertext. Key provided via `WRAPTOKEN_ENC_KEY`.
- **Bot JWT validation** -- All API requests require a valid JWT signed by the Keycloak realm, validated against JWKS with issuer and audience checks.
- **Rate limiting** -- `POST /v1/requests` is rate-limited (30 req/min per IP).
- **Request IDs** -- UUIDv4, cryptographically random and unguessable.
- **Wrap TTL capping** -- Requested TTLs are capped to the service's `max_ttl`.
- **Request expiry** -- Pending requests expire after 15 minutes. Old requests are cleaned up after 1 hour.
- **No sensitive data in logs** -- Passwords, tokens, and secrets are never logged.
- **Headless browser isolation** -- Each login gets a fresh browser context, closed after use.

### Risk: Storing Approver Credentials

The broker stores a real Keycloak user's password (`KEYCLOAK_PASSWORD`) in a Kubernetes Secret. Recommendations:

- Use a **dedicated service account user** with minimal permissions (only the ability to authenticate and trigger Duo).
- Set **short Keycloak session timeouts** for this user.
- Restrict the Kubernetes Secret with RBAC so only the broker pod can read it.
- Rotate the password regularly.
- Consider using Vault itself to store the password and bootstrapping via a different auth method.

## Admin CLI

The `bin/xpass-admin.py` script provides a unified CLI for setup and deployment:

```bash
# Discover Vault config and write xpass-admin.yaml
bin/xpass-admin.py init --vault-addr https://vault.example.com --vault-token hvs.xxx

# Configure build settings (registry, image, tag)
bin/xpass-admin.py configure

# Create Kubernetes secret
bin/xpass-admin.py create-secret \
  --keycloak-client-secret '...' \
  --keycloak-password '...' \
  --generate-enc-key

# Configure Vault OIDC auth
bin/xpass-admin.py vault-setup \
  --vault-token hvs.xxx \
  --keycloak-client-secret '...'
```

See `bin/xpass-admin.py --help` for full usage.

### Multi-Bot Sync

The `sync` subcommand reads a declarative YAML config and ensures Vault policies, OIDC roles, and Keycloak users match the desired state. It supports multi-bot isolation where each bot gets its own scoped credentials.

```bash
# Show planned changes (default)
bin/xpass-admin.py sync --vault-token $VAULT_TOKEN

# Read-only check, exit code 2 if drift detected
bin/xpass-admin.py sync --vault-token $VAULT_TOKEN --check

# Apply changes
bin/xpass-admin.py sync --vault-token $VAULT_TOKEN --apply

# With OIDC client secret (needed for Vault OIDC config + IdP admin checks)
bin/xpass-admin.py sync --vault-token $VAULT_TOKEN --oidc-client-secret $OIDC_CLIENT_SECRET --apply
```

#### Example Config (2 bots)

```yaml
vault:
  addr: https://vault.example.com
  oidc_mount: wyrd_auth
  oidc_role_prefix: ""
  allowed_redirect_uris: http://localhost:8250/oidc/callback
  user_claim: preferred_username
  bound_claim_key: preferred_username
  token_ttl: 15m
  kv_mount: projects
  kv_version: 2
  secret_prefix: xpass
  wrap_ttl: 300s
  policies:
    shared_policy_name: xpass-shared-read
    bot_policy_prefix: xpass-bot-

oidc:
  issuer_url: https://keycloak.example.com/realms/REALM
  client_id: wyrd-x-pass
  client_password: ""            # OIDC client secret (or pass via --oidc-client-secret / K8s secret)
  username: openclaw-approver    # default headless login user
  callback_listen_host: 127.0.0.1
  callback_listen_port: 8250
  callback_redirect_uri: http://localhost:8250/oidc/callback

bots:
  - name: openclaw
    approver_username: openclaw-approver
    approver_email: openclaw@example.com
  - name: roadrunner
    approver_username: roadrunner-approver

kubernetes:
  namespace: default
  secret_name: x-pass-secrets
```

#### Per-Bot Isolation

The sync subcommand enforces strict secret isolation between bots using Vault's policy system:

**Secret layout** (KV v2 at `projects/`, prefix `xpass`):

| Path | Access | Capabilities |
|---|---|---|
| `projects/data/xpass/shared/*` | All bots | read |
| `projects/metadata/xpass/shared/*` | All bots | list |
| `projects/data/xpass/bots/<bot>/*` | Only that bot | read |
| `projects/metadata/xpass/bots/<bot>/*` | Only that bot | list |

**Policies created:**

- `xpass-shared-read` — read/list the shared subtree only
- `xpass-bot-<name>` — read/list the bot's own subtree AND the shared subtree

**Why this prevents cross-bot leakage:**

1. Each bot authenticates via its own OIDC role, which binds to a unique Keycloak user (`<bot>-approver`).
2. Each OIDC role attaches only the bot's own policy (`xpass-bot-<name>`).
3. Bot policies use exact path prefixes — `xpass-bot-openclaw` grants access to `bots/openclaw/*` but NOT `bots/roadrunner/*`.
4. The shared policy is embedded in each bot policy, so all bots can read shared secrets without a separate role.
5. Vault denies any path not explicitly granted by the attached policies.

#### Required Vault Permissions for Sync

The admin token used with `--vault-token` needs:

- `sys/auth` — list and enable auth methods
- `sys/mounts` — list secret engines
- `sys/policies/acl/*` — read and write policies
- `auth/<oidc_mount>/config` — read and write OIDC config
- `auth/<oidc_mount>/role/*` — read and write OIDC roles

#### Running Sync Tests

```bash
pip install -r requirements.txt
pytest tests/test_sync.py -v
```

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

### E2E Tests

E2E tests require a real Keycloak instance with Duo configured:

```bash
export E2E_KEYCLOAK_BASE_URL=https://keycloak.example.com
export E2E_KEYCLOAK_REALM=myrealm
export E2E_KEYCLOAK_CLIENT_ID=x-pass
export E2E_KEYCLOAK_CLIENT_SECRET=...
export E2E_APPROVER_USERNAME=approver
export E2E_APPROVER_PASSWORD=...
npm run test:e2e
```

## Docker

```bash
docker build -t x-pass:latest .
```

## Deployment (Helm)

```bash
# Create the secret first (or use xpass-admin.py create-secret)
bin/xpass-admin.py create-secret \
  --keycloak-client-secret '...' \
  --keycloak-password '...' \
  --generate-enc-key

# Install
helm install x-pass ./chart \
  --set keycloak.issuerURL=https://keycloak.example.com/realms/myrealm \
  --set keycloak.clientID=x-pass \
  --set vault.addr=https://vault.example.com \
  --set vault.oidcRole=wyrd-x-pass \
  --set existingSecret=x-pass-secrets
```

## Troubleshooting

### "Callback never hit" / OIDC callback timeout

- **Keycloak redirect URI**: Ensure the Keycloak client has `http://localhost:8250/oidc/callback` in its valid redirect URIs.
- **Vault role redirect URI**: Ensure the Vault OIDC role has the same URI in `allowed_redirect_uris`.
- **Port conflict**: Verify nothing else in the pod is listening on port 8250.

### "Permission denied" / 403 from Vault

- The Vault OIDC role's policies must grant read access to the requested KV v2 paths.
- Verify the Vault token has the expected policies: `vault token lookup`.

### "Duo prompt loops" or never completes

- The approver user must be enrolled in Duo with a valid device.
- Check Duo admin console for failed push attempts.
- Increase `KC_DUO_TIMEOUT` if the user is slow to respond.

### "Invalid token" / 403 on Vault KV read

- The cached Vault token may have expired. The broker automatically re-authenticates when the token expires (at 80% of lease duration).
- Check Vault audit logs for token validation errors.
- Ensure the Vault OIDC role's `token_ttl` is long enough for the operations.

## Operational Notes

- **Single replica assumption** -- The in-memory request store means only one replica should run. If scaling beyond one replica, use sticky sessions (e.g., Ingress session affinity) so the bot's GET poll hits the same pod that processed its POST.
- **Duo timeout** -- The `KC_DUO_TIMEOUT` (default 5m) determines how long the broker waits for the human to approve the Duo push. Adjust based on your organization's response time expectations.
- **Browser resource usage** -- Each pending login spawns a headless Chromium instance. Monitor memory usage and set appropriate resource limits in the Helm values.
- **Request cleanup** -- Expired and completed requests are automatically cleaned up after 1 hour.
- **Token reuse** -- The broker caches the Vault token and reuses it for multiple requests. A login mutex ensures only one OIDC flow runs at a time, even under concurrent requests.
