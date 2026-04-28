use std::{
    env,
    path::{Path, PathBuf},
    process::Command,
};

fn main() {
    println!("cargo::rustc-check-cfg=cfg(tokio_unstable)");
    println!("cargo:rerun-if-env-changed=VERGEN_GIT_DESCRIBE");
    println!("cargo:rerun-if-env-changed=CARGO_PKG_VERSION");

    if let Some(root) = workspace_root() {
        let git_head = root.join(".git").join("HEAD");
        if git_head.exists() {
            println!("cargo:rerun-if-changed={}", git_head.display());
        }
    }

    let describe = env_override()
        .or_else(git_describe)
        .unwrap_or_else(package_version_fallback);

    println!("cargo:rustc-env=VERGEN_GIT_DESCRIBE={describe}");
}

fn env_override() -> Option<String> {
    env::var("VERGEN_GIT_DESCRIBE")
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn git_describe() -> Option<String> {
    let root = workspace_root()?;
    let output = Command::new("git")
        .args([
            "describe", "--tags", "--dirty", "--always", "--match", "v*.*.*",
        ])
        .current_dir(root)
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let describe = String::from_utf8(output.stdout).ok()?;
    let describe = describe.trim().to_owned();
    (!describe.is_empty()).then_some(describe)
}

fn package_version_fallback() -> String {
    let version = env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "0.0.0".to_owned());
    format!("v{version}")
}

fn workspace_root() -> Option<PathBuf> {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").ok()?);
    ancestor_path(&manifest_dir, 2)
}

fn ancestor_path(path: &Path, depth: usize) -> Option<PathBuf> {
    path.ancestors().nth(depth).map(PathBuf::from)
}
