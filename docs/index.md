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

## Core features
- Vault KV v2 response wrapping
- OIDC + Duo MFA login automation via Playwright
- Sub‑key addressing for structured secret namespaces
- Service registry for scoped access
- Diagnostics endpoints for operators

## Quickstart
See the README for full setup steps and CLI usage.

## Links
- Source: https://github.com/Robo-D-Wyrd/agentd-secrets
- Upstream: https://github.com/waTeim/agentd-secrets
