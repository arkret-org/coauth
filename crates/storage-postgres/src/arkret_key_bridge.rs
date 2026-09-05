//! The only place this crate names the Arkret SDK's Ed25519 generation.
//!
//! `coauth-backend` owns the real boundary between `ed25519-dalek` 2.x
//! (`coauth-jose` / `coauth-keystore`) and `ed25519-dalek` 3.x (the Arkret
//! SDK) in `coauth_backend::arkret_key_bridge`. This crate sits *below* the
//! backend in the dependency graph — the backend depends on it, not the other
//! way round — so it cannot import that module and keeps a deliberately
//! minimal mirror instead.
//!
//! The mirror is `#[cfg(test)]` because that is the whole of this crate's
//! exposure: `ed25519-dalek-3` is a dev-dependency here, used only to sign the
//! Account Status fixture that `account_status`'s rollback test appends. No
//! production path in this crate touches either generation, and the guard
//! below keeps it that way.

/// Ed25519 signing key in the generation the Arkret SDK signs with
/// (`ed25519-dalek` 3.x).
pub type SdkSigningKey = ed25519_dalek_3::SigningKey;

/// Builds an SDK-generation signing key from a raw 32-byte Ed25519 seed.
///
/// An Ed25519 seed is opaque bytes in every generation, so this direction
/// cannot fail.
pub fn sdk_signing_key_from_seed_bytes(seed: &[u8; 32]) -> SdkSigningKey {
    SdkSigningKey::from_bytes(seed)
}

#[cfg(test)]
mod tests {
    use std::{fs, io};

    use camino::{Utf8Path, Utf8PathBuf};

    /// Floor for the source-tree scan below. `crates/storage-postgres/src`
    /// held 59 `.rs` files when this guard was written; the floor exists so
    /// that a directory move, a renamed crate root, or a broken relative path
    /// makes the guard fail loudly instead of passing over an empty scan.
    const MINIMUM_SCANNED_SOURCES: usize = 40;

    fn rust_sources(root: &Utf8Path, out: &mut Vec<Utf8PathBuf>) -> io::Result<()> {
        for entry in root.read_dir_utf8()? {
            let path = entry?.into_path();
            if path.is_dir() {
                rust_sources(&path, out)?;
            } else if path.extension() == Some("rs") {
                out.push(path);
            }
        }
        Ok(())
    }

    #[test]
    fn sdk_ed25519_generation_stays_in_this_module() {
        // Assembled at runtime so this file is not itself a literal match, the
        // same self-exclusion the workspace's other source-scan guards take.
        let needle = ["ed25519_dalek", "_3"].concat();
        let src_root = Utf8Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let bridge = Utf8Path::new(file!())
            .file_name()
            .expect("guard file has a name")
            .to_owned();

        let mut sources = Vec::new();
        rust_sources(&src_root, &mut sources).expect("walk crate sources");

        // Scan-surface self-check: an empty or truncated scan must fail, not
        // pass. Both halves matter - the count catches a wrong root, and the
        // anchor catches a scan that reached a tree without this module in it.
        assert!(
            sources.len() >= MINIMUM_SCANNED_SOURCES,
            "guard scanned only {} Rust sources under {}; expected at least \
             {MINIMUM_SCANNED_SOURCES}. The scan surface moved - fix the root \
             before trusting this test",
            sources.len(),
            src_root,
        );
        assert!(
            sources
                .iter()
                .any(|path| path.file_name() == Some(bridge.as_str())),
            "guard did not scan its own module ({bridge}) under {src_root}; the \
             scan surface is not the tree this guard is meant to cover",
        );

        let mut violations = Vec::new();
        for path in &sources {
            if path.file_name() == Some(bridge.as_str()) {
                continue;
            }
            let source = fs::read_to_string(path).expect("read Rust source");
            if source.contains(&needle) {
                violations.push(path.to_string());
            }
        }

        assert!(
            violations.is_empty(),
            "the Arkret SDK's ed25519-dalek generation may only be named in \
             crate::arkret_key_bridge; call that module's helpers instead of \
             the renamed crate:\n{}",
            violations.join("\n"),
        );
    }
}
