"""Invoke the pinned OIDF API runner without ignored failures or skips."""

import argparse
import json
import os
from pathlib import Path
import re
import subprocess


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--plan", required=True)
    parser.add_argument("--results", required=True, type=Path)
    args = parser.parse_args()
    source = args.source.resolve()
    config_path = args.config.resolve()
    config = json.loads(config_path.read_text())
    if not re.fullmatch(r"[a-z0-9-]+", args.plan):
        parser.error("invalid official plan name")
    plan = args.plan
    for key, value in config.get("variant", {}).items():
        if not isinstance(value, str) or not all(re.fullmatch(r"[a-z0-9_-]+", part) for part in (key, value)):
            parser.error("invalid official variant")
        plan += f"[{key}={value}]"
    if not os.environ.get("CONFORMANCE_SERVER"):
        parser.error("CONFORMANCE_SERVER must identify the running OIDF API server")
    if not os.environ.get("CONFORMANCE_DEV_MODE") and not os.environ.get("CONFORMANCE_TOKEN"):
        parser.error("external OIDF deployments require CONFORMANCE_TOKEN")
    results = args.results.resolve()
    results.mkdir(parents=True, exist_ok=True)
    subprocess.run([
        os.environ.get("PYTHON", "python3"), str(source / "scripts/run-test-plan.py"),
        "--no-parallel", "--export-dir", str(results), plan, config_path.name,
    ], cwd=config_path.parent, check=True)
    if not list(results.glob("*.zip")):
        raise RuntimeError("the official runner produced no exported test result")


if __name__ == "__main__":
    main()
