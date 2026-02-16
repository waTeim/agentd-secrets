#!/usr/bin/env python3
"""agentd-secrets smoke test -- exercises the fetch script end-to-end.

Calls fetch.py with a known test service and verifies:
  1. Exit code 0
  2. Output is valid JSON
  3. Audit log was appended

Requires a running broker and a human to approve the Duo push.
"""

import json
import os
import subprocess
import sys

AUDIT_LOG = os.environ.get("AGENTD_AUDIT_LOG", "/tmp/agentd-secrets-audit.log")
BROKER_URL = os.environ.get("AGENTD_BROKER_URL", "http://wyrd-agentd-secrets:8080")

passed = 0
failed = 0


def check(name: str, ok: bool, detail: str = "") -> None:
    global passed, failed
    if ok:
        print(f"PASS  {name}")
        passed += 1
    else:
        msg = f"FAIL  {name}"
        if detail:
            msg += f"  ({detail})"
        print(msg)
        failed += 1


def main() -> None:
    global passed, failed

    script_dir = os.path.dirname(os.path.abspath(__file__))
    fetch = os.path.join(script_dir, "fetch.py")

    # Record audit line count before test
    before = 0
    if os.path.isfile(AUDIT_LOG):
        with open(AUDIT_LOG) as f:
            before = sum(1 for _ in f)

    print("=== agentd-secrets smoke test ===")
    print(f"Broker: {BROKER_URL}")
    print("Service: logins/google")
    print()
    print("A Duo push will be sent. Please approve it.")
    print()

    # Run fetch
    result = subprocess.run(
        [sys.executable, fetch, "logins/google", "skill smoke test"],
        capture_output=True,
        text=True,
    )

    # Test 1: exit code
    check("exit code 0", result.returncode == 0, f"got {result.returncode}")

    # Test 2: valid JSON
    is_json = False
    try:
        json.loads(result.stdout)
        is_json = True
    except (json.JSONDecodeError, ValueError):
        pass
    check("output is valid JSON", is_json, f"got: {result.stdout[:200]}" if not is_json else "")

    # Test 3: audit log appended
    after = 0
    if os.path.isfile(AUDIT_LOG):
        with open(AUDIT_LOG) as f:
            after = sum(1 for _ in f)
    new_lines = after - before
    check("audit log appended", new_lines > 0, f"before={before} after={after}")

    print()
    print(f"=== Results: {passed} passed, {failed} failed ===")
    sys.exit(1 if failed > 0 else 0)


if __name__ == "__main__":
    main()
