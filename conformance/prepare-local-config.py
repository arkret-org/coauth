"""Prepare a private local Coauth fixture and an official OIDCC Config plan."""

import argparse
import base64
import json
import os
from pathlib import Path

import yaml


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
        "resources": [{"name": name} for name in ["discovery", "oauth", "human", "health"]],
        "binds": [{"address": "127.0.0.1:7080"}],
        "proxy_protocol": False,
    }]
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
            "redirect_uris": ["http://localhost:8081/test/a/coauth/callback"],
        })
    config["clients"] = clients
    config_path = out / "coauth.yaml"
    config_path.write_text(yaml.safe_dump(config, sort_keys=False))
    config_path.chmod(0o600)
    plan = {
        "alias": "coauth-local-discovery", "description": "OIDCC Config profile only",
        "publish": "none",
        "server": {"discoveryUrl": "https://localhost:8445/.well-known/openid-configuration"},
        "client": {key: clients[0][key] for key in ["client_id", "client_secret"]},
        "client2": {key: clients[1][key] for key in ["client_id", "client_secret"]},
    }
    plan_path = out / "discovery.json"
    plan_path.write_text(json.dumps(plan, indent=2) + "\n")
    plan_path.chmod(0o600)
    if os.environ.get("COAUTH_CONFORMANCE_FULL_PLANS_JSON"):
        plans = json.loads(os.environ["COAUTH_CONFORMANCE_FULL_PLANS_JSON"])
        allowed = {"basic-op", "fapi2-baseline", "mtls-baseline"}
        if not isinstance(plans, dict) or set(plans) != allowed:
            raise ValueError("full plan fixtures must contain exactly the three requested profiles")
        full_dir = out / "full-plans"
        full_dir.mkdir()
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
