#!/usr/bin/env python3
"""Build the Glory/Sapid frontend into a backend-ready static directory."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import tomllib
from ui_dependencies import cargo_metadata, sapid_stylesheet, ui_provenance

ROOT = Path(__file__).resolve().parents[1]
FRONTEND = ROOT / "crates" / "frontend"


def build_environment():
    return os.environ.copy()


def find_bindgen(env):
    lock = tomllib.loads((ROOT / "Cargo.lock").read_text(encoding="utf-8"))
    versions = {package["version"] for package in lock["package"] if package["name"] == "wasm-bindgen"}
    if len(versions) != 1:
        raise SystemExit(f"Expected one locked wasm-bindgen version, got {sorted(versions)}")
    version = versions.pop()
    candidates = [env["WASM_BINDGEN"]] if env.get("WASM_BINDGEN") else []
    if not env.get("WASM_BINDGEN"):
        cargo_home = Path(env["CARGO_HOME"]) if env.get("CARGO_HOME") else Path.home() / ".cargo"
        executable = "wasm-bindgen.exe" if os.name == "nt" else "wasm-bindgen"
        candidates.append(str(cargo_home / "bin" / executable))
        candidates.append(shutil.which("wasm-bindgen", path=env.get("PATH")) or "wasm-bindgen")
    for candidate in candidates:
        try:
            actual = subprocess.check_output([candidate, "--version"], env=env, text=True).strip()
        except (OSError, subprocess.CalledProcessError):
            continue
        if actual == f"wasm-bindgen {version}":
            return candidate
    raise SystemExit(f"Install wasm-bindgen-cli {version} or set WASM_BINDGEN to a matching CLI")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release", action="store_true")
    parser.add_argument("--out-dir", type=Path)
    args = parser.parse_args()
    env = build_environment()
    metadata = cargo_metadata(ROOT, env)
    provenance = ui_provenance(metadata)
    target = Path(metadata["target_directory"]).resolve()
    output = (args.out_dir or target / "web").resolve()
    if output == ROOT or output in ROOT.parents or output == FRONTEND or FRONTEND in output.parents:
        raise SystemExit(f"Refusing to overwrite source directory: {output}")
    print(f"Cargo target directory: {target}", flush=True)
    bindgen = find_bindgen(env)
    command = ["cargo", "build", "--locked", "-p", "coauth-frontend", "--lib", "--target", "wasm32-unknown-unknown"]
    if args.release:
        command.append("--release")
    subprocess.run(command, cwd=ROOT, env=env, check=True, timeout=3600)
    profile = "release" if args.release else "debug"
    target.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="coauth-web-", dir=target) as temporary:
        stage = Path(temporary)
        assets = stage / "assets"
        (stage / "ui-build-info.json").write_text(json.dumps(provenance, indent=2) + "\n", encoding="utf-8")
        shutil.copytree(FRONTEND / "web", stage, dirs_exist_ok=True)
        shutil.copytree(FRONTEND / "assets", assets, dirs_exist_ok=True)
        subprocess.run([
            bindgen, str(target / "wasm32-unknown-unknown" / profile / "coauth_frontend.wasm"),
            "--target", "web", "--out-name", "coauth_frontend", "--out-dir", str(assets / "pkg"),
        ], cwd=ROOT, env=env, check=True, timeout=3600)
        sapid = sapid_stylesheet(metadata)
        shutil.copy2(sapid, assets / "sapid.css")
        (stage / ".coauth-generated-web").write_text("Glory/Sapid frontend\n", encoding="utf-8")
        if output.exists() and any(output.iterdir()):
            owned = output in {target / "web", ROOT / "dist"} or (output / ".coauth-generated-web").is_file()
            if not owned:
                raise SystemExit(f"Output directory is not an owned frontend build: {output}")
            # The resolved target above must be an owned build directory, never a source ancestor.
            shutil.rmtree(output)
        output.mkdir(parents=True, exist_ok=True)
        shutil.copytree(stage, output, dirs_exist_ok=True)
    print(f"Static frontend bundle: {output}")


if __name__ == "__main__":
    main()
