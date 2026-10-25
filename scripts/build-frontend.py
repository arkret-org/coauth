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
    env = os.environ.copy()
    cache = None
    if os.name == "nt":
        cache = Path("D:/BuildCache/coauth-glory")
    elif env.get("WSL_DISTRO_NAME"):
        mounts = Path("/proc/mounts").read_text().splitlines()
        if not any(line.split()[1] == "/mnt/d" and line.split()[0].upper().startswith("D:") for line in mounts):
            raise SystemExit("Verify /mnt/d is mounted from D: before building in WSL")
        cache = Path("/mnt/d/BuildCache/coauth-glory")
    if cache:
        temporary = cache / "tmp"
        temporary.mkdir(parents=True, exist_ok=True)
        env.setdefault("CARGO_TARGET_DIR", str(cache / "target"))
        env.setdefault("CARGO_HOME", str(cache.parent / "cargo"))
        env["TEMP"] = env["TMP"] = env["TMPDIR"] = str(temporary)
        tempfile.tempdir = str(temporary)
    if os.name == "nt":
        for key in ("CARGO_HOME", "CARGO_TARGET_DIR"):
            if Path(env[key]).resolve().drive.lower() != "d:":
                raise SystemExit(f"{key} must be on D:")
    elif env.get("WSL_DISTRO_NAME"):
        for key in ("CARGO_HOME", "CARGO_TARGET_DIR"):
            if not Path(env[key]).resolve().is_relative_to("/mnt/d"):
                raise SystemExit(f"{key} must be on the verified /mnt/d mount")
    return env


def find_bindgen(env):
    lock = tomllib.loads((ROOT / "Cargo.lock").read_text(encoding="utf-8"))
    versions = {package["version"] for package in lock["package"] if package["name"] == "wasm-bindgen"}
    if len(versions) != 1:
        raise SystemExit(f"Expected one locked wasm-bindgen version, got {sorted(versions)}")
    version = versions.pop()
    candidates = [env["WASM_BINDGEN"]] if env.get("WASM_BINDGEN") else []
    if os.name == "nt" and not candidates:
        candidates.extend(str(path) for path in Path("D:/BuildCache").glob(
            f"*/tools/wasm-bindgen-{version}-*/wasm-bindgen.exe"))
        candidates.extend(str(path) for path in (
            Path("D:/BuildCache/coauth-glory/tools/bin/wasm-bindgen.exe"),
            Path(f"D:/BuildCache/tools/wasm-bindgen/{version}/bin/wasm-bindgen.exe"),
        ) if path.is_file())
    if not env.get("WASM_BINDGEN"):
        candidates.append(shutil.which("wasm-bindgen") or "wasm-bindgen")
    for candidate in candidates:
        try:
            actual = subprocess.check_output([candidate, "--version"], env=env, text=True).strip()
        except (OSError, subprocess.CalledProcessError):
            continue
        if actual == f"wasm-bindgen {version}":
            return candidate
    raise SystemExit(f"Install wasm-bindgen-cli {version} on D: or set WASM_BINDGEN to a matching CLI")


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
    if os.name == "nt" and (target.drive.lower() != "d:" or output.drive.lower() != "d:"):
        raise SystemExit(f"Build and web output must be on D:, got {target}, {output}")
    if env.get("WSL_DISTRO_NAME") and not all(path.is_relative_to("/mnt/d") for path in (target, output)):
        raise SystemExit("Build and web output must stay on the verified /mnt/d mount")
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
