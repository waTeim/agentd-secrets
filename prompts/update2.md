# Task: Extend the admin tool to validate & construct Vault/Keycloak robot-secret security setup from config (idempotent)

## Context
We have an admin tool repository that already manages some setup for our robot-secret broker (“agentd-secrets”). We now want it to:
- Read a YAML configuration file describing expected Vault + Keycloak settings
- Check the current state in Vault/Keycloak and report drift/missing resources
- If missing or incorrect, create/update resources to match the config
- Enforce a security strategy to prevent accidental secret leakage between multiple bots:
  - Shared secrets available to all bots
  - Per-bot secrets isolated by path + policy + Vault OIDC role

Environment:
- Vault OSS, version ~1.21.x
- Keycloak version ~26.5.x with Duo configured in Keycloak (Keycloak handles 2FA; do not implement Duo logic here)
- KV engine is mounted at a configurable mount path (example in prod: `projects/` KV v2)
- OIDC auth mount exists or must be created (example: `wyrd_auth/`)
- Vault OIDC uses Keycloak as the issuer

We have (or will have) bots such as:
- openclaw
- roadrunner
Each bot must not be able to read other bots’ secrets from Vault, but all may read shared secrets.

## Desired Secret Layout Strategy (must implement)
Given a KV v2 mount `kv_mount` and prefix `secret_prefix` (example `projects` + `agentd-secrets`):
- Shared secrets live under:
  - `<kv_mount>/data/<secret_prefix>/shared/*` (KV v2 read)
  - `<kv_mount>/metadata/<secret_prefix>/shared/*` (KV v2 list)
- Bot-private secrets live under:
  - `<kv_mount>/data/<secret_prefix>/bots/<bot_name>/*`
  - `<kv_mount>/metadata/<secret_prefix>/bots/<bot_name>/*`

Vault security:
- For each bot `<bot_name>`, create a dedicated Vault policy `agentd-secrets-bot-<bot_name>` granting:
  - read/list bot-private subtree for that bot
  - read/list shared subtree
- Create a shared-only policy `agentd-secrets-shared-read` (read/list shared subtree)
- Create a Vault OIDC role per bot named exactly `<bot_name>` (or configurable prefix), under `auth/<oidc_mount>/role/<role>`
  - The role binds to a Keycloak claim (configurable):
    - preferred_username == `<bot_name>-approver` OR email == `<some email>`
  - The role attaches only policies:
    - `agentd-secrets-bot-<bot_name>` (which already includes shared)
  - The role sets:
    - `allowed_redirect_uris` to include the localhost callback (emulating `vault login -method=oidc`): `http://localhost:8250/oidc/callback`
    - `bound_audiences` to the Keycloak client id (config)
    - `ttl` per config

Keycloak setup:
- A Keycloak OIDC client exists (configurable `client_id`) used by Vault OIDC
- The Keycloak client must allow redirect URIs listed in the Vault role(s) (especially the localhost callback)
- A Keycloak user exists per bot approver identity (e.g. `openclaw-approver`, `roadrunner-approver`) OR an email-based claim mapping
- This admin tool should verify Keycloak client redirect URIs include the required redirects. It should also verify users exist. It should NOT configure Duo; Keycloak already handles that.

Important: Never allow arbitrary Vault paths from bots. This tool only ensures infrastructure resources exist. The broker will maintain a strict allowlist mapping of secret names to vault paths.

## Input Configuration
Config file is YAML with sections like:

vault:
  addr: https://vault.example.com
  oidc_mount: wyrd_auth
  oidc_role_prefix: ""          # if set, role names become "<prefix><bot_name>" else just "<bot_name>"
  allowed_redirect_uris: http://localhost:8250/oidc/callback
  user_claim: preferred_username # or email
  bound_claim_key: preferred_username
  token_ttl: 15m
  kv_mount: projects
  kv_version: 2
  secret_prefix: agentd-secrets
  wrap_ttl: 300s
  policies:
    shared_policy_name: agentd-secrets-shared-read
    bot_policy_prefix: agentd-secrets-bot-
keycloak:
  issuer_url: https://keycloak.example.com/realms/<REALM>
  client_id: agentd-secrets
  # client_secret is stored in Kubernetes secret; admin tool may need it to update Vault auth config
bots:
  - name: openclaw
    approver_username: openclaw-approver   # if binding by preferred_username
    approver_email: you@example.com        # if binding by email
  - name: roadrunner
    approver_username: roadrunner-approver

kubernetes:
  namespace: default
  secret_name: agentd-secrets-secrets
  # keys inside this k8s secret may include keycloak_client_secret, bot passwords, etc.

The tool should accept:
- `--config <path>`
- `--check` (report drift, no writes, exit non-zero if drift)
- `--apply` (idempotent create/update; safe to re-run)
- `--plan` (show planned changes without applying)
- `--init-config` (already implemented in prior work; keep)

## Required Implementation

### A) Vault checks & construction (idempotent)
Using Vault HTTP API (preferred via python hvac, or Node equivalent if tool is Node; match existing repo language):
1. Verify KV mount exists at `kv_mount` and is KV v2. If absent and operator flag permits, enable it. (If enabling is out of scope, fail with clear message.)
2. Verify OIDC auth mount exists at `oidc_mount`. If absent, enable it (`oidc`).
3. Verify `auth/<oidc_mount>/config` matches issuer (discovery URL), client id, client secret, default role (if used).
4. Ensure shared policy exists and matches exact expected HCL for shared subtree.
5. For each bot:
   - Ensure bot policy exists and matches expected HCL for bot subtree + shared subtree.
   - Ensure OIDC role exists and matches expected binding:
     - `user_claim`, `bound_claims`, `bound_audiences`, `allowed_redirect_uris`, `policies`, `ttl`, `oidc_scopes`
6. Report drift in a human-readable plan:
   - missing resource
   - resource exists but differs (show diff summary)
   - resource correct

Policies MUST use KV v2 endpoints:
- read: `<kv_mount>/data/<prefix>/...`
- list: `<kv_mount>/metadata/<prefix>/...`

### B) Keycloak checks & (optional) construction
Use Keycloak Admin REST API (or existing admin SDK in repo).
1. Verify issuer URL points to the realm expected (basic connectivity check).
2. Verify client with id `keycloak.client_id` exists.
3. Verify client has redirect URI(s) required for Vault OIDC and/or localhost callback (as specified in config).
4. Verify each approver user exists (`approver_username`). If missing:
   - either create it (if `--apply` and config provides a password source in k8s secret), OR
   - fail with a clear message describing exact missing user(s).
Prefer to support creation if secrets are available in Kubernetes; otherwise check-only.

Do not touch realm login flows or Duo plugin; this tool only verifies prerequisites for Vault OIDC.

### C) Kubernetes secret integration
The tool may need Keycloak client secret and bot user passwords. It should:
- Read Kubernetes secret `kubernetes.secret_name` in namespace
- Expect keys like:
  - `keycloak_client_secret`
  - `bot_<botname>_password` (if creating users)
- If missing, tool should still be able to run `--check` and report what’s missing.

### D) Tests
Add tests that run offline with mocks:
- Vault API mock:
  - sys/auth listing
  - sys/mounts reading for kv version
  - policy read/write
  - oidc role read/write
  - oidc config read/write
- Keycloak API mock:
  - find client by clientId
  - get/update redirect URIs
  - find/create user
- Kubernetes client mock:
  - read Secret and keys

Include at least:
- “fresh install” apply: creates everything
- “idempotent apply”: second run makes no changes
- “drift apply”: modify one policy/role, tool updates it
- “check mode”: exits non-zero when drift exists and prints plan

### E) Deliverables
1. Code changes in admin tool implementing `--check/--plan/--apply`
2. Unit tests + fixtures/mocks; `npm test` or `pytest` passes
3. Updated README: required permissions and example config for 2 bots
4. Clear explanation of how per-bot isolation works and why it prevents cross-bot leakage

## Non-goals
- Do not implement the broker runtime logic, only admin setup
- Do not implement Slack/OpenClaw integration
- Do not implement Duo configuration in Keycloak

## Notes on correctness
- Be strict about KV v2 path shapes.
- Avoid destructive changes unless explicitly flagged.
- Do not broaden policies beyond the specified subtrees.
- Ensure role/policy naming is deterministic based on bot name, to avoid accidental overlap.
