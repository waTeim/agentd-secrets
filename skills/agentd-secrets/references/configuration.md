# agentd-secrets Configuration Reference

## config.yaml

Runtime configuration for the skill, located at the skill root.

| Key | Default | Description |
|-----|---------|-------------|
| `broker_url` | `http://wyrd-agentd-secrets:8080` | Broker base URL |
| `default_wrap_ttl` | `1m` | Wrap token TTL |
| `default_requester` | `agent` | Requester identity |
| `poll_interval` | `3` | Seconds between polls |
| `poll_timeout` | `900` | Max seconds to wait for approval |
| `max_retries` | `2` | Full-flow retries on unwrap failure |
| `storage` | `ephemeral` | Storage policy (secrets to stdout only) |
| `audit_log` | `/tmp/agentd-secrets-audit.log` | Audit log path |
| `enable_auto_infer` | `false` | Enable intent-to-service mapping |

## Environment Variable Overrides

Environment variables take precedence over config.yaml when using `scripts/fetch.py`:

| Variable | Default | Maps to |
|----------|---------|---------|
| `AGENTD_BROKER_URL` | `http://wyrd-agentd-secrets:8080` | `broker_url` |
| `AGENTD_POLL_TIMEOUT` | `900` | `poll_timeout` |
| `AGENTD_POLL_INTERVAL` | `3` | `poll_interval` |
| `AGENTD_MAX_RETRIES` | `2` | `max_retries` |
| `AGENTD_AUDIT_LOG` | `/tmp/agentd-secrets-audit.log` | `audit_log` |

## Audit Log Format

Append-only, one line per invocation:

```
2026-02-16T03:12:45Z OK service=logins/google request_id=550e8400-... requester=agent
2026-02-16T03:15:00Z DENIED service=logins/github request_id=661f9500-... reason="MFA rejected"
2026-02-16T03:20:00Z FAIL service=logins/google request_id=772a0600-... error="Poll timeout"
```

Outcomes: OK, DENIED, EXPIRED, FAIL, UNWRAP_FAIL, TIMEOUT.
