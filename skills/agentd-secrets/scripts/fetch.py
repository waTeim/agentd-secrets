#!/usr/bin/env python3
"""agentd-secrets fetch -- single-command secret retrieval via the broker.

Usage: fetch.py <service> <reason> [requester] [wrap_ttl]

Requires: Python 3.8+, no third-party packages (stdlib only).
Secrets are printed to stdout as JSON. Nothing is written to disk.
"""

import json
import os
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

# ── defaults / env overrides ────────────────────────────────────────────────

BROKER_URL = os.environ.get("AGENTD_BROKER_URL", "http://wyrd-agentd-secrets:8080").rstrip("/")
POLL_TIMEOUT = int(os.environ.get("AGENTD_POLL_TIMEOUT", "900"))
POLL_INTERVAL = int(os.environ.get("AGENTD_POLL_INTERVAL", "3"))
MAX_RETRIES = int(os.environ.get("AGENTD_MAX_RETRIES", "2"))
AUDIT_LOG = os.environ.get("AGENTD_AUDIT_LOG", "/tmp/agentd-secrets-audit.log")


def log(msg: str) -> None:
    print(f"[agentd-secrets] {msg}", file=sys.stderr)


def audit(entry: str) -> None:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        with open(AUDIT_LOG, "a") as f:
            f.write(f"{ts} {entry}\n")
    except OSError as e:
        log(f"Warning: could not write audit log: {e}")


def fail(msg: str, service: str = "", reason: str = "", requester: str = "") -> None:
    audit(f'FAIL service={service} reason="{reason}" requester={requester} error="{msg}"')
    log(f"ERROR: {msg}")
    sys.exit(1)


def http_json(url: str, method: str = "GET", data: dict | None = None,
              headers: dict | None = None) -> tuple[int, dict]:
    """Make an HTTP request and return (status_code, parsed_json)."""
    hdrs = headers or {}
    body = None
    if data is not None:
        body = json.dumps(data).encode()
        hdrs["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=body, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        try:
            resp_body = json.loads(e.read())
        except Exception:
            resp_body = {}
        return e.code, resp_body
    except urllib.error.URLError as e:
        return 0, {"error": str(e.reason)}


def main() -> None:
    if len(sys.argv) < 3:
        print("Usage: fetch.py <service> <reason> [requester] [wrap_ttl]", file=sys.stderr)
        sys.exit(1)

    service = sys.argv[1]
    reason = sys.argv[2]
    requester = sys.argv[3] if len(sys.argv) > 3 else "agent"
    wrap_ttl = sys.argv[4] if len(sys.argv) > 4 else "1m"

    # ── discovery ───────────────────────────────────────────────────────────
    log(f"Discovering broker at {BROKER_URL} ...")
    status, discovery = http_json(f"{BROKER_URL}/")
    if status == 0 or "vault_addr" not in discovery:
        fail(f"Cannot reach broker at {BROKER_URL}", service, reason, requester)

    vault_addr = discovery["vault_addr"]
    services = discovery.get("services", [])
    svc_prefix = service.split("/")[0]
    if svc_prefix not in services:
        fail(f"Service prefix '{svc_prefix}' not found. Available: {', '.join(services)}",
             service, reason, requester)

    # ── retry loop ──────────────────────────────────────────────────────────
    for attempt in range(1, MAX_RETRIES + 2):
        log(f"Attempt {attempt}: requesting {service} ...")

        # 1. POST request
        status, create_resp = http_json(f"{BROKER_URL}/v1/requests", method="POST", data={
            "service": service,
            "reason": reason,
            "requester": requester,
            "wrap_ttl": wrap_ttl,
        })
        if status != 202 or "request_id" not in create_resp:
            fail(f"POST /v1/requests failed (HTTP {status}): {json.dumps(create_resp)}",
                 service, reason, requester)

        request_id = create_resp["request_id"]
        log(f"Request created: {request_id} -- waiting for Duo approval ...")

        # 2. Poll
        deadline = time.monotonic() + POLL_TIMEOUT
        poll_resp: dict = {}
        req_status = ""

        while time.monotonic() < deadline:
            _, poll_resp = http_json(f"{BROKER_URL}/v1/requests/{request_id}")
            req_status = poll_resp.get("status", "")

            if req_status == "APPROVED":
                break
            if req_status in ("DENIED", "FAILED"):
                failure = poll_resp.get("failure_reason", "unknown")
                audit(f'DENIED service={service} request_id={request_id} reason="{failure}"')
                fail(f"Request {req_status}: {failure}", service, reason, requester)
            if req_status == "EXPIRED":
                audit(f"EXPIRED service={service} request_id={request_id}")
                fail(f"Request expired (no approval within {POLL_TIMEOUT}s)",
                     service, reason, requester)

            time.sleep(POLL_INTERVAL)

        if req_status != "APPROVED":
            audit(f"TIMEOUT service={service} request_id={request_id}")
            fail(f"Poll timeout after {POLL_TIMEOUT}s", service, reason, requester)

        # 3. Unwrap
        wrap_token = poll_resp.get("wrap_token", "")
        if not wrap_token:
            fail("Approved but no wrap_token in response", service, reason, requester)

        log("Approved. Unwrapping from Vault ...")
        unwrap_status, unwrap_resp = http_json(
            f"{vault_addr}/v1/sys/wrapping/unwrap",
            method="POST",
            headers={"X-Vault-Token": wrap_token},
        )

        if unwrap_status == 200:
            secret = unwrap_resp.get("data", {}).get("data")
            if not secret:
                fail("Unwrap succeeded but .data.data is empty", service, reason, requester)
            audit(f"OK service={service} request_id={request_id} requester={requester}")
            log("Success.")
            print(json.dumps(secret, indent=2))
            sys.exit(0)

        # Unwrap failed -- retry if attempts remain
        log(f"Unwrap failed (HTTP {unwrap_status}). Attempt {attempt} of {MAX_RETRIES + 1}.")
        if attempt > MAX_RETRIES:
            audit(f"UNWRAP_FAIL service={service} request_id={request_id} http={unwrap_status}")
            fail(f"Unwrap failed after {attempt} attempts (last HTTP {unwrap_status})",
                 service, reason, requester)

        log("Retrying full flow in 5s ...")
        time.sleep(5)


if __name__ == "__main__":
    main()
