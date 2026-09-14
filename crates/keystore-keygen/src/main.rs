//! Generate a Coauth encrypted-file KeyStore master key.
//!
//! Server startup never creates or replaces this separate custody secret.
//! Local tooling may use `--if-missing` for an idempotent bootstrap.

use std::fs::{self, OpenOptions};
use std::io::{self, Write as _};
use std::process::ExitCode;

use base64::Engine as _;
use camino::{Utf8Path, Utf8PathBuf};
use zeroize::Zeroizing;

const KEY_BYTES: usize = 32;
const USAGE: &str = "usage: coauth-keystore-keygen --output <path> [--if-missing]\n\
\n\
options:\n\
  --output <path>  destination for the base64-encoded 32-byte master key\n\
  --if-missing     succeed when an existing file contains a valid master key\n\
  -h, --help       print this help\n";

#[derive(Debug, PartialEq, Eq)]
struct Args {
    output: Utf8PathBuf,
    if_missing: bool,
}

#[derive(Debug, PartialEq, Eq)]
enum Command {
    Generate(Args),
    Help,
}

#[derive(Debug, PartialEq, Eq)]
enum GenerateOutcome {
    Created,
    ExistingValid,
}

fn parse_args(raw: impl IntoIterator<Item = String>) -> anyhow::Result<Command> {
    let mut output = None;
    let mut if_missing = false;
    let mut args = raw.into_iter();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--output" => {
                anyhow::ensure!(output.is_none(), "--output may only be specified once");
                output = Some(Utf8PathBuf::from(
                    args.next()
                        .ok_or_else(|| anyhow::anyhow!("--output needs a path"))?,
                ));
            }
            "--if-missing" => {
                anyhow::ensure!(!if_missing, "--if-missing may only be specified once");
                if_missing = true;
            }
            "-h" | "--help" => return Ok(Command::Help),
            other => anyhow::bail!("unknown argument: {other}"),
        }
    }

    let output = output.ok_or_else(|| anyhow::anyhow!("--output <path> is required"))?;
    anyhow::ensure!(
        !output.as_os_str().is_empty(),
        "--output path must not be empty"
    );
    Ok(Command::Generate(Args { output, if_missing }))
}

fn validate_key_file(path: &Utf8Path) -> anyhow::Result<()> {
    let raw = fs::read_to_string(path).map_err(|error| anyhow::anyhow!("read {path}: {error}"))?;
    let trimmed = raw.trim();
    anyhow::ensure!(!trimmed.is_empty(), "{path} is empty");

    let decoded = Zeroizing::new(
        base64::engine::general_purpose::STANDARD
            .decode(trimmed.as_bytes())
            .or_else(|_| {
                base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(trimmed.as_bytes())
            })
            .map_err(|error| anyhow::anyhow!("{path} is not valid base64: {error}"))?,
    );
    anyhow::ensure!(
        decoded.len() == KEY_BYTES,
        "{} must decode to exactly {KEY_BYTES} bytes (got {})",
        path,
        decoded.len()
    );
    Ok(())
}

fn open_new_key_file(path: &Utf8Path) -> io::Result<std::fs::File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }

    options.open(path)
}

fn generate_key_file(path: &Utf8Path, if_missing: bool) -> anyhow::Result<GenerateOutcome> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent).map_err(|error| anyhow::anyhow!("create {parent}: {error}"))?;
    }

    let mut file = match open_new_key_file(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists && if_missing => {
            validate_key_file(path)?;
            return Ok(GenerateOutcome::ExistingValid);
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            anyhow::bail!(
                "refusing to overwrite existing key file {path}; use --if-missing only for idempotent initialization"
            );
        }
        Err(error) => anyhow::bail!("create {path}: {error}"),
    };

    let result = (|| -> anyhow::Result<()> {
        let mut key = Zeroizing::new([0_u8; KEY_BYTES]);
        getrandom::fill(&mut *key)
            .map_err(|error| anyhow::anyhow!("OS randomness failed: {error}"))?;
        let encoded =
            Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(key.as_slice()));

        file.write_all(encoded.as_bytes())
            .and_then(|()| file.write_all(b"\n"))
            .and_then(|()| file.sync_all())
            .map_err(|error| anyhow::anyhow!("write {path}: {error}"))?;
        drop(file);
        validate_key_file(path)
    })();

    if let Err(error) = result {
        let _ = fs::remove_file(path);
        return Err(error);
    }

    Ok(GenerateOutcome::Created)
}

fn main() -> ExitCode {
    let command = match parse_args(std::env::args().skip(1)) {
        Ok(command) => command,
        Err(error) => {
            eprintln!("[keystore-keygen] {error}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };

    let Command::Generate(args) = command else {
        print!("{USAGE}");
        return ExitCode::SUCCESS;
    };

    match generate_key_file(&args.output, args.if_missing) {
        Ok(GenerateOutcome::Created) => {
            println!("created KeyStore master key at {}", args.output);
            ExitCode::SUCCESS
        }
        Ok(GenerateOutcome::ExistingValid) => {
            println!(
                "KeyStore master key already exists and is valid at {}",
                args.output
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("[keystore-keygen] {error}");
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_a_valid_random_master_key_without_overwriting_it() {
        let directory = tempfile::tempdir().unwrap();
        let path =
            Utf8PathBuf::from_path_buf(directory.path().join("nested").join("master-key")).unwrap();

        assert_eq!(
            generate_key_file(&path, false).unwrap(),
            GenerateOutcome::Created
        );
        validate_key_file(&path).unwrap();
        let original = fs::read(&path).unwrap();

        let error = generate_key_file(&path, false).unwrap_err();
        assert!(error.to_string().contains("refusing to overwrite"));
        assert_eq!(fs::read(&path).unwrap(), original);

        assert_eq!(
            generate_key_file(&path, true).unwrap(),
            GenerateOutcome::ExistingValid
        );
        assert_eq!(fs::read(path).unwrap(), original);
    }

    #[test]
    fn if_missing_rejects_an_invalid_existing_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = Utf8PathBuf::from_path_buf(directory.path().join("master-key")).unwrap();
        fs::write(&path, "!!!\n").unwrap();

        let error = generate_key_file(&path, true).unwrap_err();
        assert!(error.to_string().contains("not valid base64"));
        assert_eq!(fs::read_to_string(path).unwrap(), "!!!\n");
    }

    #[test]
    fn parses_the_cross_platform_cli_contract() {
        assert_eq!(
            parse_args([
                "--output".to_owned(),
                "secrets/master-key".to_owned(),
                "--if-missing".to_owned(),
            ])
            .unwrap(),
            Command::Generate(Args {
                output: Utf8PathBuf::from("secrets/master-key"),
                if_missing: true,
            })
        );
        assert_eq!(parse_args(["--help".to_owned()]).unwrap(), Command::Help);
    }

    #[cfg(unix)]
    #[test]
    fn creates_the_key_with_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().unwrap();
        let path = Utf8PathBuf::from_path_buf(directory.path().join("master-key")).unwrap();
        generate_key_file(&path, false).unwrap();

        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
