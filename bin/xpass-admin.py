#!/usr/bin/env python3
"""
x-pass admin — unified CLI for x-pass deployment tasks.

Subcommands:
    init            Query Vault and auto-populate xpass-admin.yaml
    configure       Set target image config; writes xpass-admin.yaml + build-config.json
    create-secret   Create the Kubernetes Secret for Helm deployment
    vault-setup     Configure Vault OIDC auth against Keycloak

Design note — Vault CLI-style OIDC flow
    The broker emulates `vault login -method=oidc` by starting a temporary
    localhost HTTP listener (default :8250) to capture the OIDC redirect.
    No public callback endpoint is required.  The Vault OIDC role and the
    Keycloak client must both list the localhost redirect URI in their
    allowed_redirect_uris / Valid Redirect URIs respectively.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import re
import secrets
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import yaml  # type: ignore
except ImportError:
    yaml = None

CONFIG_FILE = "xpass-admin.yaml"
BUILD_CONFIG_FILE = "build-config.json"

# Default OIDC callback settings (Vault CLI-style localhost listener)
DEFAULT_OIDC_LISTEN_HOST = "127.0.0.1"
DEFAULT_OIDC_LISTEN_PORT = 8250
DEFAULT_OIDC_REDIRECT_URI = "http://localhost:8250/oidc/callback"

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _require_yaml() -> None:
    if yaml is None:
        raise SystemExit("pyyaml is required. Run: pip install pyyaml")


def project_root() -> Path:
    """Return the directory containing this script's parent (repo root)."""
    return Path(__file__).resolve().parent.parent


def default_config_path() -> Path:
    return project_root() / CONFIG_FILE


def load_config(path: Path) -> Dict[str, Any]:
    _require_yaml()
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def save_config(config: Dict[str, Any], path: Path) -> None:
    _require_yaml()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        yaml.safe_dump(config, f, sort_keys=False)
    print(f"  Saved config: {path}")


def deep_get(d: Dict[str, Any], path: str, default: Any = None) -> Any:
    """Retrieve a nested value using a dotted path string."""
    cur: Any = d
    for p in path.split("."):
        if not isinstance(cur, dict) or p not in cur:
            return default
        cur = cur[p]
    return cur


def deep_set(d: Dict[str, Any], path: str, value: Any) -> None:
    """Set a nested value using a dotted path string."""
    parts = path.split(".")
    cur = d
    for p in parts[:-1]:
        cur = cur.setdefault(p, {})
    cur[parts[-1]] = value


def get_env_or_prompt(
    env_var: str,
    prompt: str,
    required: bool = False,
    default: Optional[str] = None,
) -> Optional[str]:
    """Get value from environment variable or prompt user interactively."""
    value = os.environ.get(env_var)
    if value:
        print(f"  {prompt}: {value} (from {env_var})")
        return value

    if sys.stdin.isatty():
        if default:
            user_input = input(f"  {prompt} [{default}]: ").strip()
            return user_input if user_input else default
        else:
            user_input = input(f"  {prompt}: ").strip()
            if required and not user_input:
                print(f"    Error: {prompt} is required")
                sys.exit(1)
            return user_input if user_input else None
    elif required and not default:
        print(f"Error: {env_var} environment variable required in non-interactive mode")
        sys.exit(1)
    return default


def normalize_mount(mount: str) -> str:
    return mount.strip().rstrip("/")


def listify(value: Optional[str]) -> List[str]:
    if not value:
        return []
    return [v.strip() for v in value.split(",") if v.strip()]


def norm_list(x: Any) -> List[str]:
    if x is None:
        return []
    if isinstance(x, list):
        return x
    if isinstance(x, str):
        return [p.strip() for p in x.split(",") if p.strip()]
    return [str(x)]


# ---------------------------------------------------------------------------
# init subcommand
# ---------------------------------------------------------------------------

def cmd_init(args: argparse.Namespace) -> int:
    """Query Vault to auto-discover configuration values."""
    try:
        import hvac
    except ImportError:
        raise SystemExit("hvac is required for init. Run: pip install hvac")

    vault_addr = args.vault_addr
    vault_token = args.vault_token

    if not vault_addr or not vault_token:
        raise SystemExit("--vault-addr and --vault-token are required for init")

    client = hvac.Client(url=vault_addr, token=vault_token)
    if not client.is_authenticated():
        raise SystemExit("Vault authentication failed (check vault addr/token).")

    print("=== x-pass admin — init ===")
    print(f"  Vault: {vault_addr}")

    config_path = Path(args.config) if args.config else default_config_path()
    config = load_config(config_path)

    # -- Discover auth mounts ------------------------------------------------
    oidc_mount = None
    try:
        auths = client.sys.list_auth_methods() or {}
        for mount_key, info in auths.items():
            auth_type = (info or {}).get("type", "")
            if auth_type == "oidc" and oidc_mount is None:
                oidc_mount = mount_key.rstrip("/")
    except Exception as e:
        print(f"  [warn] could not list auth methods: {e}")

    if oidc_mount:
        print(f"  [discovered] vault.oidc_mount = {oidc_mount}")
        deep_set(config, "vault.oidc_mount", oidc_mount)
    else:
        oidc_mount = deep_get(config, "vault.oidc_mount", "oidc")
        print(f"  [default]    vault.oidc_mount = {oidc_mount}")
        deep_set(config, "vault.oidc_mount", oidc_mount)

    deep_set(config, "vault.addr", vault_addr)
    print(f"  [set]        vault.addr = {vault_addr}")

    # -- Discover OIDC config ------------------------------------------------
    oidc_discovery_url = None
    oidc_client_id = None
    default_role = None
    try:
        r = client.read(f"auth/{oidc_mount}/config")
        if r and "data" in r:
            oidc_data = r["data"]
            oidc_discovery_url = oidc_data.get("oidc_discovery_url")
            oidc_client_id = oidc_data.get("oidc_client_id")
            default_role = oidc_data.get("default_role")
    except Exception as e:
        print(f"  [warn] could not read OIDC config: {e}")

    if oidc_discovery_url:
        print(f"  [discovered] keycloak.issuer_url = {oidc_discovery_url}")
        deep_set(config, "keycloak.issuer_url", oidc_discovery_url)
        # Derive realm from issuer URL: .../realms/<realm>
        m = re.search(r"/realms/([^/]+)/?$", oidc_discovery_url)
        if m:
            realm = m.group(1)
            print(f"  [derived]    keycloak.realm = {realm}")
            deep_set(config, "keycloak.realm", realm)
    else:
        print("  [not found]  keycloak.issuer_url")

    if oidc_client_id:
        print(f"  [discovered] keycloak.client_id = {oidc_client_id}")
        deep_set(config, "keycloak.client_id", oidc_client_id)
    else:
        print("  [not found]  keycloak.client_id")

    oidc_role = default_role or deep_get(config, "vault.oidc_role", "wyrd-x-pass")
    if default_role:
        print(f"  [discovered] vault.oidc_role = {default_role}")
    else:
        print(f"  [default]    vault.oidc_role = {oidc_role}")
    deep_set(config, "vault.oidc_role", oidc_role)

    # -- Discover OIDC role --------------------------------------------------
    try:
        r = client.read(f"auth/{oidc_mount}/role/{oidc_role}")
        if r and "data" in r:
            role_data = r["data"]

            policies = norm_list(role_data.get("policies"))
            if policies:
                policy_name = policies[0]
                print(f"  [discovered] vault.policy_name = {policy_name}")
                deep_set(config, "vault.policy_name", policy_name)
            else:
                print("  [not found]  vault.policy_name (no policies on role)")

            redirect_uris = norm_list(role_data.get("allowed_redirect_uris"))
            if redirect_uris:
                val = ",".join(redirect_uris)
                print(f"  [discovered] vault.allowed_redirect_uris = {val}")
                deep_set(config, "vault.allowed_redirect_uris", val)
                # Derive oidc_callback settings from the first localhost URI
                for uri in redirect_uris:
                    if "localhost" in uri or "127.0.0.1" in uri:
                        deep_set(config, "oidc_callback.redirect_uri", uri)
                        try:
                            from urllib.parse import urlparse
                            parsed = urlparse(uri)
                            if parsed.port:
                                deep_set(config, "oidc_callback.listen_port", parsed.port)
                            deep_set(config, "oidc_callback.listen_host", parsed.hostname or DEFAULT_OIDC_LISTEN_HOST)
                        except Exception:
                            pass
                        print(f"  [derived]    oidc_callback.redirect_uri = {uri}")
                        break

            user_claim = role_data.get("user_claim")
            if user_claim:
                print(f"  [discovered] vault.user_claim = {user_claim}")
                deep_set(config, "vault.user_claim", user_claim)

            bound_claims = role_data.get("bound_claims") or {}
            if bound_claims:
                key = next(iter(bound_claims))
                value = bound_claims[key]
                if isinstance(value, list):
                    value = value[0] if value else ""
                print(f"  [discovered] vault.bound_claim_key = {key}")
                print(f"  [discovered] vault.bound_claim_value = {value}")
                deep_set(config, "vault.bound_claim_key", key)
                deep_set(config, "vault.bound_claim_value", value)

            ttl = role_data.get("ttl")
            if ttl:
                print(f"  [discovered] vault.token_ttl = {ttl}")
                deep_set(config, "vault.token_ttl", ttl)
        else:
            print(f"  [not found]  role '{oidc_role}' not configured yet")
    except Exception as e:
        print(f"  [warn] could not read OIDC role: {e}")

    # -- Discover KV mounts and policy ---------------------------------------
    policy_name = deep_get(config, "vault.policy_name")
    if policy_name:
        try:
            pol = client.sys.read_policy(name=policy_name)
            rules = ""
            if isinstance(pol, dict):
                rules = pol.get("rules") or ""
            # Parse HCL to extract kv_mount and secret_prefix
            # e.g. path "secret/data/xpass/*"
            m = re.search(r'path\s+"([^"]+)/data/([^/]+)/\*"', rules)
            if m:
                kv_mount = m.group(1)
                secret_prefix = m.group(2)
                print(f"  [discovered] vault.kv_mount = {kv_mount}")
                print(f"  [discovered] vault.secret_prefix = {secret_prefix}")
                deep_set(config, "vault.kv_mount", kv_mount)
                deep_set(config, "vault.secret_prefix", secret_prefix)
        except Exception:
            pass

    # Fill in defaults for anything not discovered
    _defaults = {
        "vault.oidc_mount": "oidc",
        "vault.oidc_role": "wyrd-x-pass",
        "vault.policy_name": "wyrd-x-pass-read",
        "vault.allowed_redirect_uris": DEFAULT_OIDC_REDIRECT_URI,
        "vault.user_claim": "preferred_username",
        "vault.bound_claim_key": "preferred_username",
        "vault.bound_claim_value": "wyrd-x-pass-approver",
        "vault.token_ttl": "15m",
        "vault.kv_mount": "secret",
        "vault.secret_prefix": "xpass",
        "vault.wrap_ttl": "300s",
        "keycloak.client_id": "wyrd-x-pass",
        "keycloak.username": "wyrd-x-pass-approver",
        "oidc_callback.listen_host": DEFAULT_OIDC_LISTEN_HOST,
        "oidc_callback.listen_port": DEFAULT_OIDC_LISTEN_PORT,
        "oidc_callback.redirect_uri": DEFAULT_OIDC_REDIRECT_URI,
        "kubernetes.namespace": "default",
        "kubernetes.secret_name": "x-pass-secrets",
        "playwright.headless": True,
        "playwright.browser": "chromium",
        "playwright.login_timeout": "2m",
        "playwright.duo_timeout": "5m",
    }
    for key, default_val in _defaults.items():
        if deep_get(config, key) is None:
            deep_set(config, key, default_val)

    save_config(config, config_path)
    print("\n[done] init complete.")
    print("\nNOTE: The Vault OIDC role and Keycloak client must both allow")
    print(f"  the redirect URI: {deep_get(config, 'oidc_callback.redirect_uri')}")
    return 0


# ---------------------------------------------------------------------------
# configure subcommand
# ---------------------------------------------------------------------------

def cmd_configure(args: argparse.Namespace) -> int:
    """Collect target image settings, update config and build-config.json."""
    config_path = Path(args.config) if args.config else default_config_path()
    config = load_config(config_path)
    saved_target = deep_get(config, "target", {}) or {}

    print("=== x-pass admin — configure ===")
    print("\n=== Target Image ===")

    registry = args.target_registry or get_env_or_prompt(
        "TARGET_REGISTRY",
        "Registry (e.g., ghcr.io/myorg, docker.io/myuser)",
        required=True,
        default=saved_target.get("registry"),
    )

    image = args.target_image or get_env_or_prompt(
        "TARGET_IMAGE",
        "Image name",
        default=saved_target.get("image", "x-pass"),
    )

    tag = args.target_tag or get_env_or_prompt(
        "TARGET_TAG",
        "Tag",
        default=saved_target.get("tag", "latest"),
    )

    deep_set(config, "target.registry", registry)
    deep_set(config, "target.image", image)
    deep_set(config, "target.tag", tag)

    print()
    save_config(config, config_path)

    # Also write build-config.json for Makefile compatibility
    build_config = {"target": {"registry": registry, "image": image, "tag": tag}}
    build_path = project_root() / BUILD_CONFIG_FILE
    build_path.write_text(json.dumps(build_config, indent=2) + "\n")
    print(f"  Saved build config: {build_path}")

    print("\n=== Next Steps ===")
    print("  make build   # Build the image")
    print("  make push    # Build and push to registry")
    return 0


# ---------------------------------------------------------------------------
# create-secret subcommand
# ---------------------------------------------------------------------------

def generate_enc_key() -> str:
    """Generate a cryptographically random hex-encoded 32-byte key."""
    return secrets.token_hex(32)


def validate_enc_key(value: str) -> str:
    """Validate that a string is a 64-character hex string (32 bytes)."""
    if not re.fullmatch(r"[0-9a-fA-F]{64}", value):
        raise argparse.ArgumentTypeError(
            "WRAPTOKEN_ENC_KEY must be exactly 64 hex characters (32 bytes)"
        )
    return value


def build_secret(name: str, namespace: str, data: dict[str, str]):
    """Construct a V1Secret object from plain-text key/value pairs."""
    from kubernetes import client
    return client.V1Secret(
        api_version="v1",
        kind="Secret",
        metadata=client.V1ObjectMeta(
            name=name,
            namespace=namespace,
            labels={"app.kubernetes.io/managed-by": "xpass-admin"},
        ),
        type="Opaque",
        data={
            k: base64.b64encode(v.encode()).decode() for k, v in data.items()
        },
    )


def cmd_create_secret(args: argparse.Namespace) -> int:
    """Create the Kubernetes Secret for x-pass Helm deployment.

    Secret keys (aligned with Helm deployment template):
        KEYCLOAK_CLIENT_SECRET  – Keycloak confidential-client secret
        WRAPTOKEN_ENC_KEY       – Hex-encoded 32-byte AES-256 key
        KEYCLOAK_USERNAME       – Keycloak user for headless OIDC login
        KEYCLOAK_PASSWORD       – Password for the headless login user
    """
    from kubernetes import client, config as k8s_config
    from kubernetes.client.rest import ApiException

    config_path = Path(args.config) if args.config else default_config_path()
    config = load_config(config_path)

    # Load kubeconfig
    try:
        k8s_config.load_incluster_config()
    except k8s_config.ConfigException:
        k8s_config.load_kube_config()

    # Resolve values: CLI flags > config file > defaults
    secret_name = args.name or deep_get(config, "kubernetes.secret_name", "x-pass-secrets")

    if args.namespace:
        namespace = args.namespace
    else:
        cfg_ns = deep_get(config, "kubernetes.namespace")
        if cfg_ns:
            namespace = cfg_ns
        else:
            try:
                _, active_context = k8s_config.list_kube_config_contexts()
                namespace = active_context["context"].get("namespace", "default")
            except (k8s_config.ConfigException, KeyError, TypeError):
                namespace = "default"

    keycloak_username = args.keycloak_username or deep_get(
        config, "keycloak.username", "wyrd-x-pass-approver",
    )

    print("=== x-pass admin — create-secret ===")
    print(f"  Secret:    {secret_name}")
    print(f"  Namespace: {namespace}")

    data: dict[str, str] = {}

    data["KEYCLOAK_CLIENT_SECRET"] = args.keycloak_client_secret
    print("  KEYCLOAK_CLIENT_SECRET: (provided)")

    if args.generate_enc_key:
        enc_key = generate_enc_key()
        print(f"  WRAPTOKEN_ENC_KEY: (generated) {enc_key}")
    else:
        enc_key = args.wraptoken_enc_key
        print("  WRAPTOKEN_ENC_KEY: (provided)")
    data["WRAPTOKEN_ENC_KEY"] = enc_key

    data["KEYCLOAK_USERNAME"] = keycloak_username
    print(f"  KEYCLOAK_USERNAME: {keycloak_username}")

    data["KEYCLOAK_PASSWORD"] = args.keycloak_password
    print("  KEYCLOAK_PASSWORD: (provided)")

    secret = build_secret(secret_name, namespace, data)
    api = client.CoreV1Api()

    try:
        api.create_namespaced_secret(namespace=namespace, body=secret)
        print(f"\nSecret '{secret_name}' created in namespace '{namespace}'")
    except ApiException as e:
        if e.status == 409:
            if not args.force:
                print(
                    f"\nError: Secret '{secret_name}' already exists in namespace '{namespace}'",
                    file=sys.stderr,
                )
                return 1
            api.replace_namespaced_secret(name=secret_name, namespace=namespace, body=secret)
            print(f"\nSecret '{secret_name}' replaced in namespace '{namespace}'")
        else:
            raise

    print(f"\nSet in your Helm values:")
    print(f'  existingSecret: "{secret_name}"')
    return 0


# ---------------------------------------------------------------------------
# vault-setup subcommand
# ---------------------------------------------------------------------------

def ensure_oidc_auth_enabled(client, mount_point: str) -> None:
    auths = client.sys.list_auth_methods() or {}
    key = f"{mount_point}/"
    if key in auths:
        current_type = (auths[key] or {}).get("type")
        if current_type != "oidc":
            raise SystemExit(
                f"Auth mount '{mount_point}/' exists but is type '{current_type}', not 'oidc'. "
                f"Choose a different oidc_mount."
            )
        print(f"[ok] auth enabled: {mount_point}/ (type=oidc)")
        return

    print(f"[change] enabling oidc auth at: {mount_point}/")
    client.sys.enable_auth_method(method_type="oidc", path=mount_point)


def ensure_policy(client, policy_name: str, policy_hcl: str) -> None:
    existing = None
    try:
        existing = client.sys.read_policy(name=policy_name)
    except Exception:
        existing = None

    current = ""
    if isinstance(existing, dict):
        current = existing.get("rules") or ""

    if current.strip() == policy_hcl.strip():
        print(f"[ok] policy unchanged: {policy_name}")
        return

    action = "[change] updating" if current else "[change] creating"
    print(f"{action} policy: {policy_name}")
    client.sys.create_or_update_policy(name=policy_name, policy=policy_hcl)


def read_oidc_config(client, mount_point: str) -> Optional[Dict[str, Any]]:
    try:
        r = client.read(f"auth/{mount_point}/config")
        if r and "data" in r:
            return r["data"]
    except Exception:
        pass
    return None


def ensure_oidc_config(
    client,
    mount_point: str,
    discovery_url: str,
    client_id: str,
    client_secret: str,
    default_role: str,
) -> None:
    desired = {
        "oidc_discovery_url": discovery_url,
        "oidc_client_id": client_id,
        "oidc_client_secret": client_secret,
        "default_role": default_role,
    }

    current = read_oidc_config(client, mount_point) or {}

    same_non_secret = (
        current.get("oidc_discovery_url") == desired["oidc_discovery_url"]
        and current.get("oidc_client_id") == desired["oidc_client_id"]
        and current.get("default_role") == desired["default_role"]
    )
    if same_non_secret:
        print(f"[ok] oidc config looks correct (non-secret fields) at auth/{mount_point}/config")
        return

    print(f"[change] writing oidc config at auth/{mount_point}/config")
    client.write(f"auth/{mount_point}/config", **desired)


def read_oidc_role(client, mount_point: str, role_name: str) -> Optional[Dict[str, Any]]:
    try:
        r = client.read(f"auth/{mount_point}/role/{role_name}")
        if r and "data" in r:
            return r["data"]
    except Exception:
        pass
    return None


def ensure_oidc_role(
    client,
    mount_point: str,
    role_name: str,
    allowed_redirect_uris: List[str],
    bound_audiences: List[str],
    user_claim: str,
    bound_claims: Dict[str, str],
    policies: List[str],
    ttl: str,
) -> None:
    desired = {
        "role_type": "oidc",
        "allowed_redirect_uris": allowed_redirect_uris,
        "bound_audiences": bound_audiences,
        "user_claim": user_claim,
        "bound_claims": bound_claims,
        "policies": policies,
        "ttl": ttl,
        "oidc_scopes": ["openid", "profile", "email"],
    }

    current = read_oidc_role(client, mount_point, role_name) or {}

    comparable_current = {
        "allowed_redirect_uris": sorted(norm_list(current.get("allowed_redirect_uris"))),
        "bound_audiences": sorted(norm_list(current.get("bound_audiences"))),
        "user_claim": current.get("user_claim"),
        "bound_claims": current.get("bound_claims") or {},
        "policies": sorted(norm_list(current.get("policies"))),
        "ttl": current.get("ttl"),
    }
    comparable_desired = {
        "allowed_redirect_uris": sorted(desired["allowed_redirect_uris"]),
        "bound_audiences": sorted(desired["bound_audiences"]),
        "user_claim": desired["user_claim"],
        "bound_claims": desired["bound_claims"],
        "policies": sorted(desired["policies"]),
        "ttl": desired["ttl"],
    }

    if comparable_current == comparable_desired:
        print(f"[ok] oidc role unchanged: {role_name}")
        return

    print(f"[change] writing oidc role: {role_name}")
    client.write(f"auth/{mount_point}/role/{role_name}", **desired)


def build_policy_hcl(kv_mount: str, secret_prefix: str) -> str:
    return f'''\
path "{kv_mount}/data/{secret_prefix}/*" {{
  capabilities = ["read"]
}}

path "{kv_mount}/metadata/{secret_prefix}/*" {{
  capabilities = ["list"]
}}
'''


def cmd_vault_setup(args: argparse.Namespace) -> int:
    """Configure Vault OIDC auth against Keycloak.

    The Vault OIDC role is configured with the localhost redirect URI used
    by the broker's Vault CLI-style OIDC flow.  Keycloak's client must
    also list this URI in its Valid Redirect URIs.
    """
    try:
        import hvac
    except ImportError:
        raise SystemExit("hvac is required for vault-setup. Run: pip install hvac")

    config_path = Path(args.config) if args.config else default_config_path()
    config = load_config(config_path)

    def pick(cli_val: Any, keypath: str, default: Any = None) -> Any:
        if cli_val is not None and (not isinstance(cli_val, str) or cli_val.strip() != ""):
            return cli_val
        return deep_get(config, keypath, default)

    vault_addr = pick(args.vault_addr, "vault.addr")
    vault_token = args.vault_token  # always from CLI
    oidc_mount = pick(args.oidc_mount, "vault.oidc_mount", "oidc")
    oidc_role = pick(args.oidc_role, "vault.oidc_role", "wyrd-x-pass")
    vault_policy_name = pick(args.vault_policy_name, "vault.policy_name", "wyrd-x-pass-read")

    keycloak_discovery_url = pick(args.keycloak_discovery_url, "keycloak.issuer_url")
    keycloak_client_id = pick(args.keycloak_client_id, "keycloak.client_id")
    keycloak_client_secret = args.keycloak_client_secret  # always from CLI

    allowed_redirect_uris = pick(
        args.allowed_redirect_uris,
        "vault.allowed_redirect_uris",
        DEFAULT_OIDC_REDIRECT_URI,
    )

    user_claim = pick(args.user_claim, "vault.user_claim", "preferred_username")
    bound_claim_key = pick(args.bound_claim_key, "vault.bound_claim_key", "preferred_username")
    bound_claim_value = pick(args.bound_claim_value, "vault.bound_claim_value", "wyrd-x-pass-approver")

    token_ttl = pick(args.token_ttl, "vault.token_ttl", "15m")

    kv_mount = pick(args.kv_mount, "vault.kv_mount", "secret")
    secret_prefix = pick(args.secret_prefix, "vault.secret_prefix", "xpass")

    # Validate required fields
    missing = []
    for name, val in [
        ("vault-addr", vault_addr),
        ("vault-token", vault_token),
        ("keycloak-discovery-url", keycloak_discovery_url),
        ("keycloak-client-id", keycloak_client_id),
        ("keycloak-client-secret", keycloak_client_secret),
        ("allowed-redirect-uris", allowed_redirect_uris),
    ]:
        if not val:
            missing.append(name)
    if missing:
        raise SystemExit(f"Missing required fields: {', '.join(missing)}")

    mount_point = normalize_mount(str(oidc_mount))

    uri_list = listify(str(allowed_redirect_uris))
    if not uri_list:
        raise SystemExit("--allowed-redirect-uris must contain at least one URI")

    policy_hcl = build_policy_hcl(str(kv_mount), str(secret_prefix))

    vc = hvac.Client(url=str(vault_addr), token=str(vault_token))
    if not vc.is_authenticated():
        raise SystemExit("Vault authentication failed (check vault addr/token).")

    print("=== x-pass admin — vault-setup ===")
    print(f"[info] connected to Vault at {vault_addr}")

    ensure_oidc_auth_enabled(vc, mount_point)
    ensure_policy(vc, str(vault_policy_name), policy_hcl)
    ensure_oidc_config(
        vc,
        mount_point,
        str(keycloak_discovery_url),
        str(keycloak_client_id),
        str(keycloak_client_secret),
        str(oidc_role),
    )
    ensure_oidc_role(
        client=vc,
        mount_point=mount_point,
        role_name=str(oidc_role),
        allowed_redirect_uris=uri_list,
        bound_audiences=[str(keycloak_client_id)],
        user_claim=str(user_claim),
        bound_claims={str(bound_claim_key): str(bound_claim_value)},
        policies=[str(vault_policy_name)],
        ttl=str(token_ttl),
    )

    print(f"\n[done] Vault OIDC configuration complete.")
    print(f"  auth mount:    {mount_point}/")
    print(f"  role:          {oidc_role}")
    print(f"  policy:        {vault_policy_name}")
    print(f"  bound claim:   {bound_claim_key} == {bound_claim_value}")
    print(f"  redirect uris: {', '.join(uri_list)}")
    print(f"\nIMPORTANT: Ensure Keycloak client '{keycloak_client_id}' also lists")
    print(f"  these redirect URIs in its Valid Redirect URIs configuration.")
    return 0


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="xpass-admin",
        description="Unified admin CLI for x-pass deployment tasks.",
    )
    parser.add_argument(
        "--config", "-c",
        default=None,
        help=f"Path to config file (default: {CONFIG_FILE} in project root)",
    )

    subs = parser.add_subparsers(dest="command", help="Subcommand")

    # -- init ----------------------------------------------------------------
    p_init = subs.add_parser("init", help="Query Vault and auto-populate config")
    p_init.add_argument("--vault-addr", required=True, help="Vault URL")
    p_init.add_argument("--vault-token", required=True, help="Vault admin token")

    # -- configure -----------------------------------------------------------
    p_cfg = subs.add_parser("configure", help="Set target image config")
    p_cfg.add_argument("--from-env", action="store_true",
                       help="Read all values from environment variables (non-interactive)")
    p_cfg.add_argument("--target-registry", help="Target image registry")
    p_cfg.add_argument("--target-image", help="Target image name")
    p_cfg.add_argument("--target-tag", help="Target image tag")

    # -- create-secret -------------------------------------------------------
    p_sec = subs.add_parser("create-secret", help="Create K8s Secret for Helm deployment")
    p_sec.add_argument("--name", default=None,
                       help="Secret name (default: from config or 'x-pass-secrets')")
    p_sec.add_argument("--namespace", "-n", default=None,
                       help="Kubernetes namespace (default: from config or kubeconfig context)")
    p_sec.add_argument("--keycloak-client-secret", required=True,
                       help="Keycloak confidential-client secret")
    enc_grp = p_sec.add_mutually_exclusive_group(required=True)
    enc_grp.add_argument("--wraptoken-enc-key", type=validate_enc_key,
                         help="Hex-encoded 32-byte AES-256 key (64 hex chars)")
    enc_grp.add_argument("--generate-enc-key", action="store_true",
                         help="Auto-generate WRAPTOKEN_ENC_KEY")
    p_sec.add_argument("--keycloak-username", default=None,
                       help="Keycloak headless login user (default: from config or 'wyrd-x-pass-approver')")
    p_sec.add_argument("--keycloak-password", required=True,
                       help="Password for the headless login user")
    p_sec.add_argument("--force", action="store_true",
                       help="Replace the secret if it already exists")

    # -- vault-setup ---------------------------------------------------------
    p_vs = subs.add_parser("vault-setup", help="Configure Vault OIDC auth against Keycloak")
    p_vs.add_argument("--vault-addr", default=None, help="Vault URL (default: from config)")
    p_vs.add_argument("--vault-token", required=True, help="Vault admin token")
    p_vs.add_argument("--oidc-mount", default=None, help="Auth mount path (default: from config)")
    p_vs.add_argument("--oidc-role", default=None, help="Vault OIDC role name")
    p_vs.add_argument("--vault-policy-name", default=None, help="Vault policy name")
    p_vs.add_argument("--keycloak-discovery-url", default=None,
                      help="Keycloak realm URL (default: from config keycloak.issuer_url)")
    p_vs.add_argument("--keycloak-client-id", default=None, help="OIDC client id")
    p_vs.add_argument("--keycloak-client-secret", required=True, help="OIDC client secret")
    p_vs.add_argument("--allowed-redirect-uris", default=None,
                      help=f"Comma-separated allowed redirect URIs (default: {DEFAULT_OIDC_REDIRECT_URI})")
    p_vs.add_argument("--user-claim", default=None, help="Claim identifying the user")
    p_vs.add_argument("--bound-claim-key", default=None, help="Claim key to bind")
    p_vs.add_argument("--bound-claim-value", default=None, help="Claim value to bind")
    p_vs.add_argument("--token-ttl", default=None, help="Vault token TTL")
    p_vs.add_argument("--kv-mount", default=None, help="KV mount")
    p_vs.add_argument("--secret-prefix", default=None, help="Prefix under KV mount")

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    dispatch = {
        "init": cmd_init,
        "configure": cmd_configure,
        "create-secret": cmd_create_secret,
        "vault-setup": cmd_vault_setup,
    }

    return dispatch[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
