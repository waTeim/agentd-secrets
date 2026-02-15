# Helm Chart Changes (Node.js Broker Migration)

## Summary

Minimal edits to support the Node.js + Playwright broker replacing the Go UMA-based broker.

## Changes

### `values.yaml`

- **Added `approver` section** with `redirectURI`, `loginTimeout`, and `duoTimeout` defaults for the headless OIDC login flow.
- **Added `playwright` section** with `headless` (default `"true"`) and `browser` (default `"chromium"`) settings.
- **Updated `existingSecret` comment** to document the two new required secret keys: `KC_APPROVER_USERNAME` and `KC_APPROVER_PASSWORD`.

### `templates/deployment.yaml`

- **Added 7 new env vars** to the container spec:
  - `KC_APPROVER_USERNAME` — from Secret (secretKeyRef)
  - `KC_APPROVER_PASSWORD` — from Secret (secretKeyRef)
  - `KC_OIDC_REDIRECT_URI` — from `approver.redirectURI` value
  - `KC_LOGIN_TIMEOUT` — from `approver.loginTimeout` value
  - `KC_DUO_TIMEOUT` — from `approver.duoTimeout` value
  - `PLAYWRIGHT_HEADLESS` — from `playwright.headless` value
  - `PLAYWRIGHT_BROWSER` — from `playwright.browser` value
- **Added `tmp` emptyDir volume + volumeMount** at `/tmp` (500Mi limit). Required because the pod uses `readOnlyRootFilesystem: true` but Playwright/Chromium needs a writable temp directory for browser profiles and caches.

### `templates/NOTES.txt`

- Updated post-install notes to list the two new secret keys (`KC_APPROVER_USERNAME`, `KC_APPROVER_PASSWORD`).

## Why

The new broker drives a headless Chromium browser (via Playwright) to perform OIDC login + Duo MFA approval. This requires:

1. Credentials for the dedicated approver user (stored in the existing K8s Secret).
2. Configuration for timeouts and the OIDC redirect URI.
3. A writable `/tmp` for Chromium's ephemeral profile data.

## What did NOT change

- Chart name, version, appVersion (update these at release time).
- All existing env vars, volumes, probes, service, ingress, HPA, and service account templates remain unchanged.
- The `podSecurityContext` and `securityContext` remain unchanged (still `readOnlyRootFilesystem: true`, `runAsNonRoot`, all capabilities dropped).
