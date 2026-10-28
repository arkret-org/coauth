"""Prepare a private local Coauth fixture and an official OIDCC Config plan."""

import argparse
import base64
import json
import math
import os
from pathlib import Path

import yaml
from cryptography.hazmat.primitives.asymmetric import rsa

LOCAL_HANDLE = "oidf-conformance"


def write_private(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")
    path.chmod(0o600)


def signing_key(kid):
    """Generate an ephemeral RSA JWK through the maintained crypto library."""
    numbers = rsa.generate_private_key(public_exponent=65537, key_size=2048).private_numbers()

    def encode(value):
        return base64.urlsafe_b64encode(value.to_bytes((value.bit_length() + 7) // 8, "big")).decode().rstrip("=")

    return {
        "kty": "RSA", "kid": kid, "use": "sig", "alg": "PS256",
        **{name: encode(value) for name, value in {
            "n": numbers.public_numbers.n, "e": numbers.public_numbers.e,
            "d": numbers.d, "p": numbers.p, "q": numbers.q,
            "dp": numbers.dmp1, "dq": numbers.dmq1, "qi": numbers.iqmp,
        }.items()},
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("generated_config", type=Path)
    parser.add_argument("output_dir", type=Path)
    args = parser.parse_args()
    out = args.output_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)
    config = yaml.safe_load(args.generated_config.read_text())
    config["database"]["uri"] = os.environ["DATABASE_URL"]
    config["http"]["public_base_url"] = "https://localhost:8445/"
    config["http"]["issuer"] = "https://localhost:8445/"
    config["http"]["listeners"] = [{
        "name": "conformance",
        "resources": [
            *[{"name": name} for name in ["discovery", "oauth", "human", "restapi", "health"]],
            {"name": "assets", "path": os.environ["COAUTH_CONFORMANCE_ASSETS"]},
        ],
        "binds": [{"address": "127.0.0.1:7080"}],
        "proxy_protocol": False,
    }]
    # Make the normal deployment quotas explicit so browser pacing follows
    # the actual isolated fixture, including generated configs that omit
    # default-valued sections. These are the shipped login defaults.
    login_limits = config.setdefault("rate_limiting", {}).setdefault("login", {})
    login_limits.setdefault("per_ip", {"burst": 3, "per_second": 3 / 60})
    login_limits.setdefault("per_account", {"burst": 1800, "per_second": 1800 / 3600})
    rates = [login_limits[key]["per_second"] for key in ("per_ip", "per_account")]
    if any(isinstance(rate, bool) or not isinstance(rate, (int, float)) or not math.isfinite(rate) or rate <= 0 for rate in rates):
        raise ValueError("local login pacing requires finite positive configured refill rates")
    login_interval = max(1 / rate for rate in rates) + 1
    wrapping_key = out / "wrapping-key"
    wrapping_key.write_text(base64.b64encode(os.urandom(32)).decode())
    wrapping_key.chmod(0o600)
    config["secrets"] = {
        "backend": "encrypted_file", "path": str(out / "keystore.v1"),
        "master_key_file": str(wrapping_key),
    }
    clients = []
    for client_id in ["01GFWR28C4KNE04WG3HKXB7C9R", "01GFWR32NCQ12B8Z0J8CPXRRB6"]:
        clients.append({
            "client_id": client_id, "client_name": "Local OIDCC fixture",
            "client_auth_method": "client_secret_basic",
            "client_secret": base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("="),
            "redirect_uris": ["https://localhost:8446/test/a/coauth-basic/callback"],
        })
    fapi_clients = []
    secret_post_client = {
        "client_id": "01GFWR4BNFDCC4QDG6AMSP1VRR", "client_name": "Local OIDCC POST fixture",
        "client_auth_method": "client_secret_post",
        "client_secret": base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("="),
        "redirect_uris": ["https://localhost:8446/test/a/coauth-basic/callback"],
    }
    clients.append(secret_post_client)
    for index, client_id in enumerate(["01GFWR3WHR93Y5HK389H28VHZ9", "01GFWR43R2ZZ8HX9CVBNW9TJWG"]):
        key = signing_key(f"coauth-fapi-{index}")
        fapi_clients.append({"client_id": client_id, "scope": "openid profile", "jwks": {"keys": [key]}, "dpop_signing_alg": "ES256"})
        clients.append({
            "client_id": client_id, "client_name": "Local FAPI fixture",
            "client_auth_method": "private_key_jwt",
            "jwks": {"keys": [{name: value for name, value in key.items() if name not in {"d", "p", "q", "dp", "dq", "qi"}}]},
            "redirect_uris": ["https://localhost:8446/test/a/coauth-fapi/callback"] + (
                ["https://localhost:8446/test/a/coauth-fapi/callback?dummy1=lorem&dummy2=ipsum"] if index == 1 else []
            ),
        })
    config["clients"] = clients
    config_path = out / "coauth.yaml"
    config_path.write_text(yaml.safe_dump(config, sort_keys=False))
    config_path.chmod(0o600)
    plan = {
        "alias": "coauth-local-discovery", "description": "OIDCC Config profile only",
        "publish": "none",
        "server": {
            "discoveryUrl": "https://localhost:8445/.well-known/openid-configuration",
            "allow_unexpected_metadata_fields": [
                "account_management_uri", "account_management_actions_supported",
                "org.arkret.api_endpoint", "org.arkret.did_binding_methods",
                "org.arkret.supported_scopes",
            ],
        },
        "client": {key: clients[0][key] for key in ["client_id", "client_secret"]},
        "client2": {key: clients[1][key] for key in ["client_id", "client_secret"]},
    }
    plan_path = out / "discovery.json"
    plan_path.write_text(json.dumps(plan, indent=2) + "\n")
    plan_path.chmod(0o600)
    write_private(out / "browser-user.json", {
        "handle": LOCAL_HANDLE, "password": "Oidf!9" + base64.urlsafe_b64encode(os.urandom(32)).decode(),
        "login_interval_seconds": login_interval,
    })
    full_dir = out / "full-plans"
    full_dir.mkdir()
    common = {"publish": "none", "server": {**plan["server"], "login_hint": LOCAL_HANDLE}, "browser": [], "_browser_driver": "chromium"}
    write_private(full_dir / "basic-op.json", {
        **common, "alias": "coauth-basic", "description": "Local real-client Basic OP",
        "_official_plan": "oidcc-basic-certification-test-plan",
        "variant": {"server_metadata": "discovery", "client_registration": "static_client"},
        "client": {**plan["client"], "scope": "openid profile"},
        "client2": {**plan["client2"], "scope": "openid profile"},
        "client_secret_post": {**{key: secret_post_client[key] for key in ["client_id", "client_secret"]}, "scope": "openid profile"},
    })
    write_private(full_dir / "fapi2-baseline.json", {
        **common, "alias": "coauth-fapi", "description": "Local private_key_jwt and DPoP FAPI2",
        "_official_plan": "fapi2-security-profile-id2-test-plan",
        # The official ID2 plan itself fixes unsigned/plain_response per module;
        # supplying either fixed variant again is rejected by VariantService.
        "variant": {"client_auth_type": "private_key_jwt", "fapi_profile": "plain_fapi",
                    "sender_constrain": "dpop", "openid": "openid_connect", "authorization_request_type": "simple"},
        "client": fapi_clients[0], "client2": fapi_clients[1],
        "resource": {"resourceUrl": "https://localhost:8445/oauth/userinfo"},
    })
    write_private(full_dir / "mtls-baseline.json", {
        "_unavailable": "Coauth does not implement RFC8705 client authentication or certificate-bound tokens; discovery and registration deliberately exclude tls_client_auth/self_signed_tls_client_auth. This profile remains a failing product capability obligation.",
    })
    if os.environ.get("COAUTH_CONFORMANCE_FULL_PLANS_JSON"):
        plans = json.loads(os.environ["COAUTH_CONFORMANCE_FULL_PLANS_JSON"])
        allowed = {"basic-op", "fapi2-baseline", "mtls-baseline"}
        if not isinstance(plans, dict) or set(plans) != allowed:
            raise ValueError("full plan fixtures must contain exactly the three requested profiles")
        for name, profile in plans.items():
            if not isinstance(profile, dict) or not profile.get("_official_plan"):
                raise ValueError(f"{name} must identify its real official plan")
            if not profile.get("browser"):
                raise ValueError(f"{name} requires real-user browser login/consent automation")
            discovery = profile.get("server", {}).get("discoveryUrl", "")
            if not discovery.startswith("https://"):
                raise ValueError(f"{name} requires a reachable HTTPS issuer")
            path = full_dir / f"{name}.json"
            path.write_text(json.dumps(profile) + "\n")
            path.chmod(0o600)


if __name__ == "__main__":
    main()
