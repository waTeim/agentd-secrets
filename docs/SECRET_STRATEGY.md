# Secret Strategy (Meta)

This note captures the **meta‑strategy** we use for secrets in OpenClaw workflows.
It’s meant to keep access reliable over time **without ever storing secret values**.

## Principles

1) **Discover first**
   - Use agentd‑secrets path discovery as the source of truth.
   - If a likely secret path isn’t listed, assume it hasn’t been recorded yet.
   - Only ask to create/store new secrets when discovery doesn’t show a match.

2) **Record locations, not values**
   - Store *only* the Vault path and key name (never the secret itself).
   - Example:
     - GitHub PAT is stored at `secret://tokens` key `github_pat`.

3) **Default to documenting access**
   - Whenever access is gated by a secret and we successfully retrieve it,
     we record *how to retrieve it* (path + key) in long‑term memory.

## Why this works

- **Security:** no secrets at rest in docs or memory.
- **Durability:** after restarts, we can re‑acquire secrets via Vault.
- **Clarity:** future work doesn’t require replaying old Q&A.

## Recommended workflow

1) Run discovery:
   - `curl -sS http://<broker>/v1/paths`
2) If a likely path exists, request via agentd‑secrets:
   - `python3 scripts/fetch.py <path> "reason"`
3) Store *only* the path + key in long‑term memory (not the value).

---

If the path is missing, treat it as **not recorded yet** and ask to store it.
