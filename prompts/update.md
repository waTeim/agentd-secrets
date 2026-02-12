# Task: Modify the xpass broker to emulate `vault login -method=oidc` (Vault CLI-style localhost callback)

## Context
We have an existing Node.js broker service (built for Kubernetes) that uses Playwright to automate authentication. We previously considered OIDC callbacks to the broker service, but we are changing design: **emulate Vault CLI OIDC login**:
- The broker should start a temporary local HTTP listener (like Vault CLI does on `http://localhost:8250/oidc/callback`).
- The broker should obtain Vault tokens by using Vault’s **OIDC auth method endpoints** and completing the flow by receiving the redirect on localhost.
- The broker should not need a public callback endpoint and should not require Keycloak API integration beyond browser automation.

Vault version is 1.21.2. Keycloak is 26.5.x and is configured with Duo via a Keycloak provider; the “push approve” happens inside Keycloak login.

The Keycloak OIDC client exists: `wyrd-x-pass`.
The Keycloak user exists: `wyrd-x-pass-approver`.
Vault has OIDC auth enabled at some mount (default: `oidc/`) and a role (default: `wyrd-x-pass`) allowing the redirect URI `http://localhost:8250/oidc/callback` (and any other required redirects we decide). If needed, document Vault role requirements but do not implement Vault config code in this change.

## Goal
Implement a broker login flow that:
1. Calls Vault to get an OIDC auth URL.
2. Starts a local callback listener like the Vault CLI.
3. Uses Playwright to open the auth URL and complete Keycloak login + Duo push.
4. Captures the redirect to localhost and completes the Vault callback exchange to obtain a Vault token.
5. Uses that Vault token to read secrets (KV v2) and return a wrapped response token (Vault response wrapping) to the caller (OpenClaw handles Slack; broker is only HTTP API).

## Requirements / Design Constraints
- Kubernetes deployment. Do NOT assume local desktop browser. The browser automation runs inside the broker pod.
- No public callback endpoint is required; callback stays on localhost inside the pod.
- Prefer **idempotent / robust** behavior with clear logging and timeouts.
- Handle concurrency safely: multiple requests might try to login at once.
  - Option A (simplest): serialize logins with a single login mutex and reuse the token for a short TTL window (configurable) until it expires.
  - Option B: choose a random local port per login; BUT that requires Vault role to allow those redirect URIs (Vault doesn’t accept wildcards), so only do this if you also provide a clear operator doc and a configurable fixed set of allowed ports/URIs.
  - Choose Option A unless there’s a strong reason otherwise.
- Tests must be included (unit tests + minimal integration-style tests using mocks). No real Vault/Keycloak required in tests.
- Update Helm chart values docs if any ports/paths/config changed.

## What to Implement

### 1) Add a Vault OIDC login module (new)
Implement a module/class (e.g., `src/auth/vaultOidcCliFlow.ts`) that performs:

**Step 1: Get auth URL from Vault**
Call Vault endpoint to get auth URL (Vault OIDC auth method):
- `POST /v1/auth/<mount>/oidc/auth_url` OR `GET` depending on Vault endpoint requirements.
- Provide parameters including at least:
  - `role`: Vault role name (e.g., `wyrd-x-pass`)
  - `redirect_uri`: `http://localhost:8250/oidc/callback` (default)
  - `client_nonce`: random string (store to verify if returned)
  - optionally `state`: random string for correlation
Return includes an `auth_url` (string). (If endpoint response differs, adapt accordingly—be faithful to Vault API docs for OIDC auth method.)

**Step 2: Start local callback listener**
Start an HTTP server listening on `127.0.0.1` (default port 8250) and handle `GET /oidc/callback`.
Capture the incoming query parameters (usually includes `code` and `state`; Vault expects these for callback exchange).
- Must support a timeout.
- Must be able to shut down cleanly.
- Store the captured params and resolve a promise.

**Step 3: Drive browser automation**
Launch Playwright (Chromium) and open the `auth_url`.
Automate Keycloak login:
- Fill username/password for `wyrd-x-pass-approver` (source from broker config/secret).
- Duo push: wait for completion (poll UI state until redirect occurs).
- The browser will redirect to `http://localhost:8250/oidc/callback?...`.
The local listener catches the request and extracts query params. Once captured, close browser context.

**Step 4: Exchange callback with Vault**
Call Vault endpoint:
- `POST /v1/auth/<mount>/oidc/callback` with the captured query params (or as payload required by Vault).
Vault returns `auth.client_token` (Vault token) and metadata.

Return this Vault token to the broker logic. Store it in memory with TTL (based on Vault response lease duration if present, else config TTL).

### 2) Use Vault token to read secrets
Implement a function to read a named secret:
- Resolve secret name -> Vault path mapping (existing broker config likely already has this).
- Read KV v2: `GET /v1/<kvMount>/data/<path>` (or use an existing client wrapper).
- Return secret fields.
- Must enforce allowlist: only configured secret “names” are accessible; no arbitrary paths.

### 3) Response wrapping output
When returning a secret to OpenClaw, do NOT return the raw secret.
Instead:
- Use Vault response wrapping (wrap TTL configurable, default 60s–5m).
- Call Vault with `X-Vault-Wrap-TTL: <ttl>` header when reading the secret or when generating response payload (depending on existing broker behavior).
- Return only the wrapping token to the caller.
- Ensure the wrapping token is single-use and expires.

### 4) Broker API changes (if needed)
If the broker currently has endpoints like:
- `POST /v1/request-secret` with `{name: "svcA"}`
Keep API stable unless you must change.
Return `{wrap_token: "...", expires_in: ...}`.

### 5) Configuration changes
Add config fields (via env/config file or K8s secret/values—match repo conventions):
- `VAULT_ADDR`
- `VAULT_OIDC_MOUNT` (default `oidc`)
- `VAULT_OIDC_ROLE` (default `wyrd-x-pass`)
- `VAULT_KV_MOUNT` (default `secret`)
- `VAULT_WRAP_TTL` (default `300s`)
- `OIDC_LOCAL_LISTEN_HOST` (default `127.0.0.1`)
- `OIDC_LOCAL_LISTEN_PORT` (default `8250`)
- `OIDC_LOCAL_REDIRECT_URI` (default `http://localhost:8250/oidc/callback`)
- Keycloak login creds for the broker user:
  - `KEYCLOAK_USERNAME` (wyrd-x-pass-approver)
  - `KEYCLOAK_PASSWORD`
- Playwright headless and timeout tuning.

IMPORTANT: Since we are emulating Vault CLI, the redirect URI is localhost. Ensure operator docs explain that Vault role must include this exact URI in allowed_redirect_uris and Keycloak client must allow it too.

### 6) Concurrency and caching policy
Implement a login/token cache:
- Keep `vaultToken` in memory with expiration.
- If a request needs a token and the cached token is valid, reuse it.
- If no valid token, acquire it via OIDC flow with a mutex/lock so only one login happens at a time.
- If acquisition fails, do not poison cache; return a clear error.

### 7) Tests
Add tests covering:
- Getting auth_url from Vault (mock HTTP).
- Local callback server captures query params and shuts down.
- Callback exchange returns token and caches it.
- Secret read uses token; wrap TTL header is applied.
- Concurrency: two simultaneous requests trigger only one login flow.
Use:
- jest or vitest
- nock/msw to mock Vault HTTP
- a “fake playwright” adapter: abstract the Playwright actions behind an interface so tests can simulate “browser reached redirect URL”.

Do NOT require a real browser in unit tests; keep one optional integration test behind a flag if you want.

### 8) Helm chart update
Since callback is localhost, broker does NOT need to expose a public `/oidc/callback` service route.
- Ensure service ports are still correct for broker public API.
- No ingress changes needed for callback.
- Add values for the new config items and ensure secrets are created/mounted.

### 9) Docs
Update IMPLEMENTATION.md or README:
- Explain the Vault CLI-style OIDC flow and why callback is localhost inside pod.
- List required Keycloak client redirect URI and Vault role allowed_redirect_uris.
- Provide troubleshooting tips:
  - “callback never hit” (Keycloak blocked localhost redirect; wrong URI)
  - “permission denied” (Vault role/policy)
  - “Duo prompt loops” (user enrollment)
  - “403 invalid token” (Vault token expired; verify renew behavior)

## Deliverables
1) PR-quality code modifications with clean structure.
2) Unit tests + mocks; `npm test` passes.
3) Updated Helm values + documentation.
4) Short “How the flow works” sequence diagram or bullet list.

## Notes
- Do not reintroduce UMA. That approach is discarded.
- Keep integrations with Slack/OpenClaw out of scope.
- Focus on correctness, robustness, and a minimal operational footprint.
