# CLAUDE.md -- Development Guide for agentd-secrets

## Project Overview

agentd-secrets is a secret access broker that mediates access to HashiCorp Vault secrets with human-in-the-loop Duo MFA approval. The API requires no caller authentication -- access control is enforced by the human approver accepting or rejecting the Duo push. Internally, it uses Playwright to drive headless browser OIDC login flows against Vault.

## Architecture

- **TypeScript/Express server** (`src/`) -- API server handling secret requests, polling, and diagnostics
- **Python admin CLI** (`bin/agentd-secrets-admin.py`) -- Vault setup, sync, secret management, Helm values generation
- **Helm chart** (`chart/`) -- Kubernetes deployment
- **Skill file** (`skills/agentd-secrets.md`) -- Agent-consumable guide for using the broker API

### Key Source Files

| File | Purpose |
|------|---------|
| `src/server.ts` | Express app setup, middleware, route mounting |
| `src/routes.ts` | API routes (`/v1/requests`), health checks, diag endpoints, `GET /` discovery |
| `src/worker.ts` | Async request processor (OIDC login -> Vault read -> encrypt wrap token) |
| `src/config.ts` | Config loading, service registry, `resolveService()` with sub-key addressing |
| `src/requestStore.ts` | In-memory request lifecycle (create -> approve/deny/expire -> cleanup) |
| `src/vaultClient.ts` | Vault HTTP client (token caching, renewal, wrapped KV reads) |
| `src/auth/vaultOidcCliFlow.ts` | OIDC CLI-style login flow orchestration with mutex |
| `src/playwrightDriver.ts` | Headless browser driver with Duo interstitial handling |
| `src/jwtMiddleware.ts` | JWT validation (currently unused -- API endpoints have no auth) |
| `src/encryption.ts` | AES-256-GCM encrypt/decrypt for wrap tokens at rest |
| `bin/agentd-secrets-admin.py` | Admin CLI (init, vault-setup, sync, create-secret, put/get/list-secret) |
| `tests/test_sync.py` | Python tests for the sync subcommand |

## Build and Test

```bash
# TypeScript
npm install
npm run build
npm test               # all tests
npm run test:unit      # unit only
npm run test:integration  # integration only
npx tsc --noEmit       # type check without emitting

# Python (admin CLI tests)
pip install -r requirements.txt
pytest tests/test_sync.py -v

# Docker
docker build -t agentd-secrets:latest .

# Helm
helm lint ./chart
helm template ./chart
```

## Code Conventions

- TypeScript strict mode; no `any` types
- Express routes return early on validation errors (no nested if/else)
- Vault tokens cached with 80% lease duration TTL; mutex-serialized login
- Config loaded from env vars + YAML service registry
- Admin CLI uses argparse subcommands; config stored in `agentd-secrets-config.yaml`
- Admin CLI config keys use dot notation: `vault.kv_mount`, `oidc.issuer_url`, `vault.role.token_ttl`
- Service registry supports sub-key addressing: `logins/google` matches `logins` entry, appends `/google` to `kv2_path`
- `kv2_mount` in service registry is optional; defaults to global `vault.kvMount`
- Container runs as `agentd` user (UID/GID 1500), read-only root filesystem
- Playwright browsers at `/usr/local/lib/pw-browsers`

## Common Pitfalls

- Vault OIDC config requires exactly ONE of: `oidc_discovery_url`, `jwks_url`, `jwt_validation_pubkeys`, `jwks_pairs`. Never send both `oidc_discovery_url` and `jwks_url`.
- Bare `*` in YAML is an alias indicator. Use `"0.0.0.0"` or quote `"*"` for listen hosts. The admin CLI's `normalize_host()` maps `*` to `0.0.0.0`.
- The Playwright callback promise must have `.catch(() => {})` attached immediately to prevent unhandled rejection crashes on timeout.
- Vault KV v2 API paths include `/data/` prefix: `<mount>/data/<path>`. The `vaultClient.readWrapped()` adds this automatically.
- Token TTL vs lease duration: Vault may report a longer `leaseDuration` than the actual token TTL. The broker uses 80% of reported duration as its validity window.
