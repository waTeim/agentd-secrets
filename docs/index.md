---
layout: default
title: agentd-secrets
---

# agentd-secrets

![agentd-secrets banner](banner.png)

**Secret access broker for HashiCorp Vault with OIDC + Duo MFA approval.**

Agentd‑secrets is a Node.js/TypeScript service that lets bots and automation request Vault secrets, while a human approves each request via Duo push. The broker never returns plaintext secrets — only short‑lived Vault wrapping tokens.

## Why this exists
- **Human approval** for every sensitive secret read
- **No plaintext** secret handling inside the broker
- **Fast onboarding** with an admin CLI and Helm chart
- **Kubernetes‑friendly** deployment model

## Purpose (OpenClaw agents)
agentd‑secrets is built for OpenClaw agents that need secrets on‑demand, with a human approving each request via Duo.
The broker returns only short‑lived Vault wrapping tokens, keeping plaintext secrets out of agent logs and runtime state.

**Read more:** [Secret strategy](SECRET_STRATEGY.md)

## Core features
- Vault KV v2 response wrapping
- OIDC + Duo MFA login automation via Playwright
- Sub‑key addressing for structured secret namespaces
- Service registry for scoped access
- Diagnostics endpoints for operators

## Quickstart
See the README for full setup steps and CLI usage.

## GitHub example (OpenClaw agent PAT)
1) Store a GitHub PAT in Vault under `tokens` with key `github_pat`.
2) From an OpenClaw agent, request it with a reason (Duo approval required).
3) Use it in‑memory only (no file writes), then discard.

Example:
```bash
python3 scripts/fetch.py tokens "Need GitHub PAT for repo ops"
```

## Links
- Source: https://github.com/Robo-D-Wyrd/agentd-secrets
- Upstream: https://github.com/waTeim/agentd-secrets
