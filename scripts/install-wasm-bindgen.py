#!/usr/bin/env python3
"""Install the browser binding CLI selected by this workspace's Cargo.lock."""
import argparse
import os
from pathlib import Path
import re
import shutil
import subprocess
import tomllib

from ui_dependencies import cargo_environment


def locked_version(lockfile):
    lock = tomllib.loads(lockfile.read_text(encoding="utf-8"))
    versions = {item["version"] for item in lock["package"] if item["name"] == "wasm-bindgen"}
    if len(versions) != 1:
        raise RuntimeError("Cargo.lock must select exactly one wasm-bindgen version")
    version = versions.pop()
    if not isinstance(version, str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise RuntimeError("Cargo.lock contains an unsupported wasm-bindgen version")
    return version


def cli_version(command, environment):
    try:
        return subprocess.check_output(
            [command, "--version"], env=environment, text=True, timeout=15
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def install(lockfile, environment):
    version = locked_version(lockfile)
    expected = f"wasm-bindgen {version}"
    selected = environment.get("WASM_BINDGEN")
    home = environment.get("CARGO_HOME")
    home_command = str(Path(home) / "bin" / ("wasm-bindgen.exe" if os.name == "nt" else "wasm-bindgen")) if home else None
    command = selected or home_command or shutil.which("wasm-bindgen", path=environment.get("PATH")) or "wasm-bindgen"
    if cli_version(command, environment) == expected:
        return version
    if selected:
        raise RuntimeError("Explicit WASM_BINDGEN does not match Cargo.lock")
    install_command = ["cargo", "install", "--locked", "--version", "=" + version, "wasm-bindgen-cli"]
    if home:
        install_command.extend(["--root", home])
    subprocess.run(
        install_command,
        cwd=lockfile.parent,
        env=environment,
        check=True,
        timeout=900,
    )
    command = home_command or shutil.which("wasm-bindgen", path=environment.get("PATH")) or "wasm-bindgen"
    if cli_version(command, environment) != expected:
        raise RuntimeError("Installed wasm-bindgen CLI is not the locked version on PATH")
    return version


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--lockfile", type=Path,
        default=Path(__file__).resolve().parents[1] / "Cargo.lock",
    )
    args = parser.parse_args()
    lockfile = args.lockfile.resolve(strict=True)
    environment = cargo_environment(lockfile.parent)
    version = install(lockfile, environment)
    print(f"Locked wasm-bindgen CLI ready: {version}", flush=True)


if __name__ == "__main__":
    main()
