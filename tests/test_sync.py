"""Tests for the agentd-secrets-admin sync subcommand."""
from __future__ import annotations

import base64
import copy
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest import mock

import pytest

# Ensure bin/ is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "bin"))

import importlib
xpass_admin = importlib.import_module("agentd-secrets-admin")


# ---------------------------------------------------------------------------
# Mock Vault client
# ---------------------------------------------------------------------------

class MockVaultSys:
    """Mock for hvac.Client.sys.*"""

    def __init__(self, state: dict):
        self._state = state  # shared mutable state dict

    def list_auth_methods(self) -> dict:
        # Return full Vault response envelope (hvac >= 2.x style)
        return {
            "request_id": "mock-req",
            "lease_id": "",
            "renewable": False,
            "lease_duration": 0,
            "data": dict(self._state.get("auth_methods", {})),
        }

    def list_mounted_secrets_engines(self) -> dict:
        return {
            "request_id": "mock-req",
            "lease_id": "",
            "renewable": False,
            "lease_duration": 0,
            "data": dict(self._state.get("secret_engines", {})),
        }

    def enable_auth_method(self, method_type: str, path: str) -> None:
        key = f"{path}/"
        self._state.setdefault("auth_methods", {})[key] = {
            "type": method_type,
            "description": "",
            "config": {},
        }

    def enable_secrets_engine(self, backend_type: str, path: str, options: dict = None) -> None:
        key = f"{path}/"
        self._state.setdefault("secret_engines", {})[key] = {
            "type": backend_type,
            "options": options or {},
        }

    def read_policy(self, name: str) -> dict:
        policies = self._state.get("policies", {})
        if name not in policies:
            raise Exception(f"policy not found: {name}")
        # Return full Vault response envelope (hvac >= 2.x style)
        return {
            "request_id": "mock-req",
            "data": {"name": name, "rules": policies[name]},
        }

    def create_or_update_policy(self, name: str, policy: str) -> None:
        self._state.setdefault("policies", {})[name] = policy


class MockVaultClient:
    """Mock for hvac.Client"""

    def __init__(self, state: Optional[dict] = None):
        self._state = state if state is not None else {
            "auth_methods": {},
            "secret_engines": {},
            "policies": {},
            "data": {},  # path -> {data: {...}}
        }
        self.sys = MockVaultSys(self._state)

    def is_authenticated(self) -> bool:
        return True

    def read(self, path: str) -> Optional[dict]:
        if path in self._state.get("data", {}):
            return self._state["data"][path]
        return None

    def write(self, path: str, **kwargs) -> None:
        self._state.setdefault("data", {})[path] = {"data": kwargs}


# ---------------------------------------------------------------------------
# Mock OIDC responses
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Test configuration
# ---------------------------------------------------------------------------

def make_config(
    bots: Optional[list] = None,
    kv_mount: str = "projects",
    secret_prefix: str = "agentd-secrets",
    oidc_mount: str = "wyrd_auth",
) -> dict:
    if bots is None:
        bots = [
            {"name": "openclaw", "approver_username": "openclaw-approver", "approver_email": "openclaw@example.com"},
            {"name": "roadrunner", "approver_username": "roadrunner-approver"},
        ]
    return {
        "vault": {
            "addr": "https://vault.example.com",
            "oidc_mount": oidc_mount,
            "oidc_role_prefix": "",
            "allowed_redirect_uris": "http://localhost:8250/oidc/callback",
            "user_claim": "preferred_username",
            "bound_claim_key": "preferred_username",
            "token_ttl": "15m",
            "kv_mount": kv_mount,
            "kv_version": 2,
            "secret_prefix": secret_prefix,
            "wrap_ttl": "300s",
            "policies": {
                "shared_policy_name": "agentd-secrets-shared-read",
                "bot_policy_prefix": "agentd-secrets-bot-",
            },
        },
        "oidc": {
            "issuer_url": "https://idp.example.com/realms/REALM",
            "client_id": "agentd-secrets",
        },
        "bots": bots,
        "kubernetes": {
            "namespace": "default",
            "secret_name": "openclaw-agentd-secrets",
        },
    }


def make_vault_state(
    with_kv: bool = False,
    with_oidc_mount: bool = False,
) -> dict:
    """Build initial Vault mock state."""
    state: dict = {
        "auth_methods": {},
        "secret_engines": {},
        "policies": {},
        "data": {},
    }
    if with_kv:
        state["secret_engines"]["projects/"] = {
            "type": "kv",
            "options": {"version": "2"},
        }
    if with_oidc_mount:
        state["auth_methods"]["wyrd_auth/"] = {
            "type": "oidc",
            "description": "",
            "config": {},
        }
    return state


def make_args(
    config_path: str = "/tmp/test-config.yaml",
    vault_token: str = "test-token",
    dry_run: bool = False,
) -> mock.MagicMock:
    args = mock.MagicMock()
    args.config = config_path
    args.vault_token = vault_token
    args.dry_run = dry_run
    return args


# ---------------------------------------------------------------------------
# Helper to run sync with mocked deps
# ---------------------------------------------------------------------------

def run_sync(
    config: dict,
    vault_state: dict,
    args: Optional[mock.MagicMock] = None,
    k8s_secrets: Optional[dict] = None,
) -> tuple:
    """Run cmd_sync with mocked dependencies. Returns (exit_code, vault_state, plan_items)."""
    if args is None:
        args = make_args()

    mock_client = MockVaultClient(vault_state)
    captured_plan_items: List[xpass_admin.PlanItem] = []

    original_print_plan = xpass_admin.print_plan

    def capture_print_plan(items):
        captured_plan_items.extend(items)
        original_print_plan(items)

    # Patch load_config
    with mock.patch.object(xpass_admin, "load_config", return_value=config):
        # Patch hvac.Client
        with mock.patch("hvac.Client", return_value=mock_client):
            # Patch read_k8s_secret
            with mock.patch.object(
                xpass_admin, "read_k8s_secret", return_value=k8s_secrets or {}
            ):
                # Patch check_oidc_discovery (network call)
                with mock.patch.object(
                    xpass_admin, "check_oidc_discovery",
                    return_value=xpass_admin.PlanItem("oidc_discovery", config.get("oidc", {}).get("issuer_url", ""), "ok"),
                ):
                    with mock.patch.object(xpass_admin, "print_plan", capture_print_plan):
                        exit_code = xpass_admin.cmd_sync(args)

    return exit_code, vault_state, captured_plan_items


# ===========================================================================
# Test cases
# ===========================================================================

class TestPolicyHCLBuilders:
    """Test that policy HCL is generated correctly."""

    def test_shared_policy_hcl(self):
        hcl = xpass_admin.build_shared_policy_hcl("projects", "agentd-secrets")
        assert 'path "projects/data/agentd-secrets/shared/*"' in hcl
        assert '"read"' in hcl
        assert 'path "projects/metadata/agentd-secrets/shared/*"' in hcl
        assert '"list"' in hcl
        # Should NOT contain bot paths
        assert "bots" not in hcl

    def test_bot_policy_hcl(self):
        hcl = xpass_admin.build_bot_policy_hcl("projects", "agentd-secrets", "openclaw")
        # Bot-specific paths
        assert 'path "projects/data/agentd-secrets/bots/openclaw/*"' in hcl
        assert 'path "projects/metadata/agentd-secrets/bots/openclaw/*"' in hcl
        # Also includes shared
        assert 'path "projects/data/agentd-secrets/shared/*"' in hcl
        assert 'path "projects/metadata/agentd-secrets/shared/*"' in hcl

    def test_bot_policy_isolation(self):
        """Bot A's policy must not grant access to bot B's paths."""
        hcl_a = xpass_admin.build_bot_policy_hcl("projects", "agentd-secrets", "openclaw")
        hcl_b = xpass_admin.build_bot_policy_hcl("projects", "agentd-secrets", "roadrunner")
        assert "openclaw" in hcl_a
        assert "roadrunner" not in hcl_a
        assert "roadrunner" in hcl_b
        assert "openclaw" not in hcl_b


class TestFreshInstall:
    """Test sync --apply on an empty Vault creates all resources."""

    def test_fresh_install_apply(self):
        config = make_config()
        vault_state = make_vault_state(with_kv=True)  # KV exists, nothing else
        args = make_args()

        exit_code, state, items = run_sync(config, vault_state, args)

        assert exit_code == 0

        # OIDC mount was created
        assert "wyrd_auth/" in state["auth_methods"]

        # Shared policy was created
        assert "agentd-secrets-shared-read" in state["policies"]
        shared_hcl = state["policies"]["agentd-secrets-shared-read"]
        assert "shared" in shared_hcl

        # Bot policies were created
        assert "agentd-secrets-bot-openclaw" in state["policies"]
        assert "agentd-secrets-bot-roadrunner" in state["policies"]

        # OIDC config was written
        assert "auth/wyrd_auth/config" in state["data"]

        # OIDC roles were created
        assert "auth/wyrd_auth/role/openclaw" in state["data"]
        assert "auth/wyrd_auth/role/roadrunner" in state["data"]

        # Verify role bindings
        openclaw_role = state["data"]["auth/wyrd_auth/role/openclaw"]["data"]
        assert openclaw_role["policies"] == ["agentd-secrets-bot-openclaw"]
        assert openclaw_role["bound_claims"] == {"preferred_username": "openclaw-approver"}

        roadrunner_role = state["data"]["auth/wyrd_auth/role/roadrunner"]["data"]
        assert roadrunner_role["policies"] == ["agentd-secrets-bot-roadrunner"]
        assert roadrunner_role["bound_claims"] == {"preferred_username": "roadrunner-approver"}


class TestIdempotentApply:
    """Run sync twice; second run should produce all 'ok' items."""

    def test_idempotent(self):
        config = make_config()
        vault_state = make_vault_state(with_kv=True)
        args = make_args()

        # First apply
        exit_code1, state, items1 = run_sync(config, vault_state, args)
        assert exit_code1 == 0

        # Second apply on same state
        args2 = make_args()
        exit_code2, state, items2 = run_sync(config, state, args2)
        assert exit_code2 == 0

        # All resource items should be ok (info items are config echoes, not checks)
        non_ok = [i for i in items2 if i.status not in ("ok", "info")]
        assert len(non_ok) == 0, f"Non-ok items: {[(i.kind, i.name, i.status, i.diff) for i in non_ok]}"


class TestDriftDetection:
    """Modify a resource after first apply, then check detects drift."""

    def test_drift_check_exits_2(self):
        config = make_config()
        vault_state = make_vault_state(with_kv=True)

        # First apply
        args_apply = make_args()
        _, state, _ = run_sync(config, vault_state, args_apply)

        # Tamper with shared policy
        state["policies"]["agentd-secrets-shared-read"] = "# tampered policy"

        # Check mode
        args_check = make_args(dry_run=True)
        exit_code, _, items = run_sync(config, state, args_check)

        assert exit_code == 2
        drift_items = [i for i in items if i.status == "drift"]
        assert any(i.name == "agentd-secrets-shared-read" for i in drift_items)


class TestDriftApply:
    """Modify a policy and role, then apply fixes them."""

    def test_drift_apply_fixes(self):
        config = make_config()
        vault_state = make_vault_state(with_kv=True)

        # First apply
        args_apply = make_args()
        _, state, _ = run_sync(config, vault_state, args_apply)

        # Tamper with bot policy
        state["policies"]["agentd-secrets-bot-openclaw"] = "# tampered"

        # Tamper with role (change bound_claims)
        role_data = state["data"]["auth/wyrd_auth/role/openclaw"]["data"]
        role_data["bound_claims"] = {"preferred_username": "wrong-user"}

        # Apply again
        args_apply2 = make_args()
        exit_code, state, items = run_sync(config, state, args_apply2)

        assert exit_code == 0

        # Policy should be restored
        assert "tampered" not in state["policies"]["agentd-secrets-bot-openclaw"]
        assert "openclaw" in state["policies"]["agentd-secrets-bot-openclaw"]

        # Role should be restored
        restored_role = state["data"]["auth/wyrd_auth/role/openclaw"]["data"]
        assert restored_role["bound_claims"] == {"preferred_username": "openclaw-approver"}


class TestCheckModeOutput:
    """Verify plan output includes correct status labels."""

    def test_check_output_shows_statuses(self, capsys):
        config = make_config()
        vault_state = make_vault_state(with_kv=True)

        # Run check on empty Vault (everything missing)
        args = make_args(dry_run=True)
        exit_code, _, items = run_sync(config, vault_state, args)

        assert exit_code == 2  # drift detected
        captured = capsys.readouterr().out

        # Should show missing items
        assert "[missing]" in captured or "[drift]" in captured

        # KV mount should be ok (it exists)
        kv_items = [i for i in items if i.kind == "kv_mount"]
        assert len(kv_items) == 1
        assert kv_items[0].status == "ok"

        # OIDC mount should be missing
        oidc_items = [i for i in items if i.kind == "oidc_mount"]
        assert len(oidc_items) == 1
        assert oidc_items[0].status == "missing"


class TestMultiBotIsolation:
    """Verify bot policies enforce proper isolation."""

    def test_bot_policy_no_cross_access(self):
        config = make_config()
        vault_state = make_vault_state(with_kv=True)

        args = make_args()
        _, state, _ = run_sync(config, vault_state, args)

        openclaw_hcl = state["policies"]["agentd-secrets-bot-openclaw"]
        roadrunner_hcl = state["policies"]["agentd-secrets-bot-roadrunner"]

        # openclaw policy grants access to openclaw subtree + shared
        assert "bots/openclaw" in openclaw_hcl
        assert "shared" in openclaw_hcl
        # openclaw policy must NOT grant access to roadrunner
        assert "bots/roadrunner" not in openclaw_hcl

        # roadrunner policy grants access to roadrunner subtree + shared
        assert "bots/roadrunner" in roadrunner_hcl
        assert "shared" in roadrunner_hcl
        # roadrunner policy must NOT grant access to openclaw
        assert "bots/openclaw" not in roadrunner_hcl

    def test_shared_policy_no_bot_access(self):
        """Shared policy must not grant access to any bot subtree."""
        config = make_config()
        vault_state = make_vault_state(with_kv=True)

        args = make_args()
        _, state, _ = run_sync(config, vault_state, args)

        shared_hcl = state["policies"]["agentd-secrets-shared-read"]
        assert "shared" in shared_hcl
        assert "bots/" not in shared_hcl

    def test_each_role_gets_own_policy(self):
        """Each OIDC role should only reference its own bot policy."""
        config = make_config()
        vault_state = make_vault_state(with_kv=True)

        args = make_args()
        _, state, _ = run_sync(config, vault_state, args)

        openclaw_role = state["data"]["auth/wyrd_auth/role/openclaw"]["data"]
        assert openclaw_role["policies"] == ["agentd-secrets-bot-openclaw"]

        roadrunner_role = state["data"]["auth/wyrd_auth/role/roadrunner"]["data"]
        assert roadrunner_role["policies"] == ["agentd-secrets-bot-roadrunner"]


class TestKVMountChecks:
    """Test KV mount verification."""

    def test_kv_mount_missing_check(self):
        config = make_config()
        vault_state = make_vault_state(with_kv=False)
        args = make_args(dry_run=True)

        exit_code, _, items = run_sync(config, vault_state, args)

        kv_items = [i for i in items if i.kind == "kv_mount"]
        assert len(kv_items) == 1
        assert kv_items[0].status == "missing"
        assert kv_items[0].apply_fn is not None

    def test_kv_mount_created_on_apply(self):
        config = make_config()
        vault_state = make_vault_state(with_kv=False)
        args = make_args()

        exit_code, state, items = run_sync(config, vault_state, args)

        assert exit_code == 0
        assert "projects/" in state["secret_engines"]
        assert state["secret_engines"]["projects/"]["type"] == "kv"
        assert state["secret_engines"]["projects/"]["options"]["version"] == "2"

    def test_kv_mount_wrong_version(self):
        vault_state = make_vault_state()
        vault_state["secret_engines"]["projects/"] = {
            "type": "kv",
            "options": {"version": "1"},
        }
        config = make_config()
        args = make_args(dry_run=True)

        exit_code, _, items = run_sync(config, vault_state, args)

        kv_items = [i for i in items if i.kind == "kv_mount"]
        assert len(kv_items) == 1
        assert kv_items[0].status == "drift"


class TestPlanItem:
    """Test PlanItem basics."""

    def test_plan_item_defaults(self):
        item = xpass_admin.PlanItem("test", "test-resource")
        assert item.kind == "test"
        assert item.name == "test-resource"
        assert item.status == "ok"
        assert item.diff == ""
        assert item.apply_fn is None

    def test_print_plan(self, capsys):
        items = [
            xpass_admin.PlanItem("policy", "test-policy", "ok"),
            xpass_admin.PlanItem("policy", "drift-policy", "drift", "HCL differs"),
            xpass_admin.PlanItem("oidc_role", "missing-role", "missing", "not found"),
        ]
        xpass_admin.print_plan(items)
        out = capsys.readouterr().out
        assert "[ok]" in out
        assert "[drift]" in out
        assert "[missing]" in out
        assert "HCL differs" in out

    def test_print_plan_multiline_diff(self, capsys):
        """Multi-line diffs print each field on its own indented line."""
        items = [
            xpass_admin.PlanItem(
                "oidc_config", "auth/oidc/config", "missing",
                "oidc_discovery_url: None -> 'https://example.com/realms/master'\noidc_client_id: None -> 'agentd-secrets'",
            ),
        ]
        xpass_admin.print_plan(items)
        out = capsys.readouterr().out
        lines = out.strip().split("\n")
        # Header on its own line, then each diff field on a separate line
        assert len(lines) == 3
        assert "[missing]" in lines[0]
        assert "auth/oidc/config" in lines[0]
        assert "oidc_discovery_url:" in lines[1]
        assert "oidc_client_id:" in lines[2]


class TestOIDCRolePrefix:
    """Test that oidc_role_prefix is respected."""

    def test_role_prefix(self):
        config = make_config()
        config["vault"]["oidc_role_prefix"] = "xp-"
        vault_state = make_vault_state(with_kv=True)
        args = make_args()

        _, state, _ = run_sync(config, vault_state, args)

        # Roles should be prefixed
        assert "auth/wyrd_auth/role/xp-openclaw" in state["data"]
        assert "auth/wyrd_auth/role/xp-roadrunner" in state["data"]
