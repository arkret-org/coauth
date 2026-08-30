// ── Key Generation Routines ──
//
// Provides functions to generate fresh cryptographic keys for all
// supported algorithms, as well as a deterministic test fixture.

use anyhow::Context;
use coauth_keystore::PrivateKey;
use rand_core::{RngCore, SeedableRng};
use tokio::task;
use tracing::info;

use super::SecretsConfig;
use super::encryption::EncryptionKey;
use super::key_config::{Key, KeyConfig};

/// Holds the generation logic for [`SecretsConfig`].
impl SecretsConfig {
    /// Creates a fresh configuration with randomly-generated keys covering
    /// RSA, EC P-256, EC P-384, EC P-521, EC secp256k1, and Ed25519.
    #[expect(
        clippy::similar_names,
        reason = "Key type names are necessarily similar"
    )]
    #[tracing::instrument(skip_all)]
    pub(crate) async fn generate<R>(mut rng: R) -> anyhow::Result<Self>
    where
        R: RngCore + Send,
    {
        info!("Generating keys...");

        let rsa_key = {
            let span = tracing::info_span!("rsa");
            let key_rng = rand_chacha::ChaChaRng::from_rng(&mut rng)?;
            task::spawn_blocking(move || {
                let _entered = span.enter();
                let ret = PrivateKey::generate_rsa(key_rng).unwrap();
                info!("Done generating RSA key");
                ret
            })
            .await
            .context("could not join blocking task")?
        };

        let ec_p256_key =
            spawn_ec_keygen(&mut rng, "ec_p256", PrivateKey::generate_ec_p256).await?;
        let ec_p384_key =
            spawn_ec_keygen(&mut rng, "ec_p384", PrivateKey::generate_ec_p384).await?;
        let ec_p521_key =
            spawn_ec_keygen(&mut rng, "ec_p521", PrivateKey::generate_ec_p521).await?;
        let ec_k256_key =
            spawn_ec_keygen(&mut rng, "ec_k256", PrivateKey::generate_ec_k256).await?;
        let ed25519_key =
            spawn_ec_keygen(&mut rng, "ed25519", PrivateKey::generate_ed25519).await?;
        Ok(Self {
            encryption: EncryptionKey::Value({
                let mut key = [0u8; 32];
                rng.fill_bytes(&mut key);
                key
            }),
            keys: Some(vec![
                into_key_config(rsa_key)?,
                into_key_config(ec_p256_key)?,
                into_key_config(ec_p384_key)?,
                into_key_config(ec_p521_key)?,
                into_key_config(ec_k256_key)?,
                into_key_config_with_kid(ed25519_key, coauth_keystore::ACCOUNT_AUTHORITY_KEY_ID)?,
            ]),
            keys_dir: None,
        })
    }

    /// Returns a deterministic test configuration with hardcoded keys
    pub(crate) fn test() -> Self {
        let rsa_key = KeyConfig {
            kid: None,
            password: None,
            key: Key::Value(
                indoc::indoc! {r"
                  -----BEGIN PRIVATE KEY-----
                  MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEAymS2RkeIZo7pUeEN
                  QUGCG4GLJru5jzxomO9jiNr5D/oRcerhpQVc9aCpBfAAg4l4a1SmYdBzWqX0X5pU
                  scgTtQIDAQABAkEArNIMlrxUK4bSklkCcXtXdtdKE9vuWfGyOw0GyAB69fkEUBxh
                  3j65u+u3ZmW+bpMWHgp1FtdobE9nGwb2VBTWAQIhAOyU1jiUEkrwKK004+6b5QRE
                  vC9UI2vDWy5vioMNx5Y1AiEA2wGAJ6ETF8FF2Vd+kZlkKK7J0em9cl0gbJDsWIEw
                  N4ECIEyWYkMurD1WQdTQqnk0Po+DMOihdFYOiBYgRdbnPxWBAiEAmtd0xJAd7622
                  tPQniMnrBtiN2NxqFXHCev/8Gpc8gAECIBcaPcF59qVeRmYrfqzKBxFm7LmTwlAl
                  Gh7BNzCeN+D6
                  -----END PRIVATE KEY-----
                "}
                .to_owned(),
            ),
        };
        let ecdsa_key = KeyConfig {
            kid: None,
            password: None,
            key: Key::Value(
                indoc::indoc! {r"
                  -----BEGIN PRIVATE KEY-----
                  MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgqfn5mYO/5Qq/wOOiWgHA
                  NaiDiepgUJ2GI5eq2V8D8nahRANCAARMK9aKUd/H28qaU+0qvS6bSJItzAge1VHn
                  OhBAAUVci1RpmUA+KdCL5sw9nadAEiONeiGr+28RYHZmlB9qXnjC
                  -----END PRIVATE KEY-----
                "}
                .to_owned(),
            ),
        };

        Self {
            encryption: EncryptionKey::Value([0xEA; 32]),
            keys: Some(vec![rsa_key, ecdsa_key]),
            keys_dir: None,
        }
    }
}

// ── Internal Helpers ──

/// Spawns a blocking task that generates a single elliptic-curve or
/// Edwards-curve private key using the provided `gen_fn`, seeded from `rng`.
async fn spawn_ec_keygen<R, F>(rng: &mut R, label: &str, gen_fn: F) -> anyhow::Result<PrivateKey>
where
    R: RngCore,
    F: FnOnce(rand_chacha::ChaChaRng) -> PrivateKey + Send + 'static,
{
    let span = tracing::info_span!(target: "secrets_keygen", "keygen", algorithm = label);
    let child_rng = rand_chacha::ChaChaRng::from_rng(rng)?;
    let algo_label = label.to_owned();

    task::spawn_blocking(move || {
        let _entered = span.enter();
        let pk = gen_fn(child_rng);
        info!("Done generating {algo_label} key");
        pk
    })
    .await
    .context("could not join blocking key generation task")
}

/// Wraps a [`PrivateKey`] into a [`KeyConfig`] carrying its PEM encoding
fn into_key_config(pk: PrivateKey) -> anyhow::Result<KeyConfig> {
    Ok(KeyConfig {
        kid: None,
        password: None,
        key: Key::Value(pk.to_pem(pem_rfc7468::LineEnding::LF)?.to_string()),
    })
}

fn into_key_config_with_kid(pk: PrivateKey, kid: &str) -> anyhow::Result<KeyConfig> {
    Ok(KeyConfig {
        kid: Some(kid.to_owned()),
        password: None,
        key: Key::Value(pk.to_pem(pem_rfc7468::LineEnding::LF)?.to_string()),
    })
}
