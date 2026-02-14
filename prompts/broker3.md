# Prompt: Rebuild agentd-secrets broker as Node.js + Playwright (Keycloak IdP, Duo in Browser flow)

You are a senior security engineer and Node.js backend developer. Re-implement the existing “agentd-secrets” secret broker as a wholly Node.js service that uses a headless browser (Playwright) to obtain a Keycloak user token via OIDC Authorization Code + PKCE, rather than UMA/RPT polling. Maintain compatibility with the existing Helm chart/env/secret/config expectations described below.

## Repo layout assumption (IMPORTANT)

- You are working in a **new repository** for the Node.js broker.
- The existing **Helm chart source has been copied into `./helm/`** from the old repo and should be treated as authoritative.
- **Do not redesign the chart.** Make the Node broker conform to it.
- If chart changes are required (e.g., add new Secret keys or env vars for Playwright login), apply them as **minimal edits** in-place under `./helm/` and also provide a short `./helm/CHANGES.md` describing exactly what changed and why.
- **Do not assume the previous Go broker source code is available.** Only the Helm chart is carried over.

## Context: existing broker (for compatibility)

The current agentd-secrets broker sits between an automated client (bot) and HashiCorp Vault. It enforces “human-in-the-loop approval” by relying on Keycloak as the authorization gate. It never stores actual secrets; it only returns Vault response-wrapping tokens, encrypted at rest with AES-256-GCM using a 32-byte key in `WRAPTOKEN_ENC_KEY` (hex). It exposes:

- `POST /v1/requests` → returns `{request_id, status:PENDING_APPROVAL}`
- `GET /v1/requests/{id}` → returns status; once approved returns `{wrap_token}`
- `/healthz`, `/readyz` (ready checks Keycloak discovery reachable and Vault sys/health)

Requests are ephemeral (in-memory). Worker pool handles async processing. JWT middleware validates bot JWTs against Keycloak JWKS. Helm chart mounts a service registry YAML at `/etc/agentd-secrets/config.yaml`, injects Keycloak and Vault env vars, and uses a Secret with `KEYCLOAK_CLIENT_SECRET` and `WRAPTOKEN_ENC_KEY`. Keep these behaviors/knobs.

## New behavior to implement

Replace the UMA/RPT “approval” with a headless Keycloak login performed by the broker:

- Keycloak is the IdP for a dedicated “agent” user.
- The Keycloak realm’s Browser authentication flow includes Duo MFA (via a Keycloak Duo plugin). Approval is accomplished when the human approves the Duo push on their phone.
- The broker must initiate an OIDC Authorization Code flow (with PKCE S256) to Keycloak, drive the login in Playwright headless Chromium, wait for Duo approval to complete, capture the redirect with the authorization code, and exchange it for tokens at the token endpoint.
- The broker then uses the resulting Keycloak token (or simply treats successful completion as “approved”) to proceed with reading from Vault using response wrapping and returning the wrap token to the bot.

**Critical UX constraint:** The bot must never ask the human to paste codes. Approval must be via Duo push only (the human taps approve in Duo Mobile). The human is not required to open a browser intentionally; any webview/headless steps are broker-internal.

## What must remain true

1. Broker never returns plaintext secrets—only Vault wrapping tokens (single-use) and only decrypts stored wrap tokens when responding to `GET /v1/requests/{id}`.
2. Wrap tokens are encrypted at rest using AES-256-GCM with a hex-encoded 32-byte key `WRAPTOKEN_ENC_KEY` (64 hex chars). Nonce prepended to ciphertext.
3. Bot must authenticate to broker using Bearer JWT validated against Keycloak JWKS; validate issuer/audience per env vars.
4. Service registry defines “named services” mapping to:
   - Vault KV v2 mount/path
   - wrap TTL caps/defaults  
   (Authz/UMA fields may remain for backward compatibility but are not used for gating in the new version unless explicitly needed.)
5. Vault auth method stays Kubernetes auth (login using serviceaccount token), token cached and renewed; read KV v2 secret with `X-Vault-Wrap-TTL`.
6. `/readyz` checks Keycloak discovery + Vault sys/health.
7. In-memory request store and single-replica assumption is acceptable (document sticky sessions if scaled).

## Required configuration (match Helm/env contract)

Read env vars compatible with the existing chart:

- `KEYCLOAK_ISSUER_URL`, `KEYCLOAK_REALM`, `KEYCLOAK_CLIENT_ID`, `KEYCLOAK_CLIENT_SECRET`, optional `KEYCLOAK_AUDIENCE`
- `VAULT_ADDR`, `VAULT_K8S_AUTH_PATH`, `VAULT_K8S_ROLE`, `VAULT_K8S_JWT_PATH`
- `WRAPTOKEN_ENC_KEY` (hex)
- `BROKER_LISTEN_ADDR` (default `:8080`)

Read service registry YAML from `/etc/agentd-secrets/config.yaml` (as mounted by the Helm chart).

### Add new env vars for headless auth

Document and add to Helm chart only if not already present; keep defaults sensible:

- `KC_APPROVER_USERNAME` (the Keycloak user that logs in)
- `KC_APPROVER_PASSWORD` (stored in a Kubernetes Secret; never logged)
- `KC_OIDC_REDIRECT_URI` (broker’s callback URL; can be internal-only)
- `KC_LOGIN_TIMEOUT` (e.g. 2m) and `KC_DUO_TIMEOUT` (e.g. 5m)
- `PLAYWRIGHT_HEADLESS` (true)
- `PLAYWRIGHT_BROWSER` (chromium)

## Core API contract

Implement:

- `POST /v1/requests` body: `{ service, reason, requester, wrap_ttl? }`
  - Validate service exists in registry, cap wrap_ttl to max_ttl.
  - Create request with status `PENDING_APPROVAL`, expires at now+15m.
  - Enqueue async worker job.
- `GET /v1/requests/{id}` returns status. If `APPROVED`, include decrypted `wrap_token` and `wrap_expires_at`.
- Terminal states: `APPROVED`, `DENIED`, `EXPIRED`, `FAILED`.
  - `DENIED` represents Duo denial or inability to complete login due to rejection.
  - `FAILED` is any error (Keycloak, Playwright, Vault).

## Worker pipeline (new)

For each request:

1) Perform headless OIDC login against Keycloak using Playwright:

- Construct auth URL from OIDC discovery (`.well-known/openid-configuration`).
- Use Authorization Code + PKCE S256: generate verifier/challenge, state, nonce.
- Launch headless browser context (new context per request).
- Navigate to auth URL.
- Fill in Keycloak login page with `KC_APPROVER_USERNAME` + `KC_APPROVER_PASSWORD`.
- Submit and then wait until the flow completes after Duo approval.
- Capture the redirect to `KC_OIDC_REDIRECT_URI` with `code` and `state`.
- Exchange code at token endpoint (include `code_verifier`) to obtain tokens (access token at minimum).
- Verify token signature/issuer/audience as a sanity check.
- (Optional) Cache refresh token/session to reduce repeated Duo prompts; only if safe and documented. If caching, encrypt at rest with `WRAPTOKEN_ENC_KEY` or a separate key.

2) Vault:

- Login via Kubernetes auth if needed, cache token.
- Read KV v2 secret with `X-Vault-Wrap-TTL` (effective TTL).
- Extract `wrap_info.token`.

3) Encrypt wrap token, store request as `APPROVED` with wrap expiry.

## Playwright robustness requirements

- Use deterministic selectors for Keycloak username/password fields and submit button (support configurable selectors if needed).
- Implement timeouts and retries (but never infinite loops).
- Ensure the browser is closed in all cases.
- Never log HTML content that could include sensitive data.
- Record structured audit logs: request_id, service, requester, outcome, timings.

## Security requirements

- Never log `KC_APPROVER_PASSWORD`, Vault tokens, Keycloak tokens, or wrap tokens.
- Encrypt wrap tokens at rest (AES-256-GCM).
- Rate-limit `POST /v1/requests`.
- Ensure request_id is unguessable (UUIDv4).
- Ensure wrap_ttl is short and capped.
- Document risks of storing a real user password in broker; recommend using a dedicated user with minimal permissions and short sessions.

## Tests & tooling

Provide:

- Unit tests for config parsing, TTL capping, encryption/decryption, request state machine, JWT middleware.
- Integration-style tests with HTTP mocks for:
  - Keycloak OIDC discovery + token exchange
  - Vault K8s auth login + wrapped KV read
- For Playwright: provide tests that can be run in CI as “optional” (skipped unless `E2E_KEYCLOAK_BASE_URL` is set), and unit-test the Playwright driver via interface mocking.
- Linting + formatting scripts.

## Deliverables

Output a repo with:

- `src/` Node service (TypeScript preferred)
- `Dockerfile` suitable for Kubernetes (include Playwright deps)
- `README.md` with: how it works, security notes, config reference, operational notes (single replica, sticky sessions if scaling)
- `./helm/CHANGES.md` describing minimal Helm edits you made (if any)

Implement fully—no TODO placeholders. Keep the external contract (endpoints, env var names, service registry path) compatible with the existing agentd-secrets deployment described above, and keep the Helm chart in `./helm/` as the deployment contract.
