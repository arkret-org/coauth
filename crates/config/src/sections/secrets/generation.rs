//! Generation and binary envelope for the complete Coauth runtime key bundle.

use anyhow::{Context, ensure};
use coauth_keyring::PrivateKey;
use rand_core::{RngCore, SeedableRng};
use tokio::task;
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"COAUTHK1";
const FORMAT_VERSION: u16 = 1;
const INITIAL_KEY_COUNT: usize = 8;
const MAX_KEY_COUNT: usize = 64;

pub(super) struct StoredKey {
    pub(super) kid: Option<String>,
    pub(super) der: Zeroizing<Vec<u8>>,
}

pub(super) struct StoredKeyBundle {
    pub(super) encryption_key: Zeroizing<[u8; 32]>,
    pub(super) keys: Vec<StoredKey>,
}

impl StoredKeyBundle {
    pub(super) fn encode(&self) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        ensure!(
            (1..=MAX_KEY_COUNT).contains(&self.keys.len()),
            "runtime key bundle must contain between 1 and {MAX_KEY_COUNT} keys"
        );
        let mut output = Zeroizing::new(Vec::new());
        output.extend_from_slice(MAGIC);
        output.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
        output.extend_from_slice(self.encryption_key.as_ref());
        output.extend_from_slice(
            &u16::try_from(self.keys.len())
                .context("too many stored keys")?
                .to_be_bytes(),
        );
        for key in &self.keys {
            let kid = key.kid.as_deref().unwrap_or_default().as_bytes();
            output.extend_from_slice(
                &u16::try_from(kid.len())
                    .context("stored key id is too long")?
                    .to_be_bytes(),
            );
            output.extend_from_slice(kid);
            output.extend_from_slice(
                &u32::try_from(key.der.len())
                    .context("stored private key is too large")?
                    .to_be_bytes(),
            );
            output.extend_from_slice(&key.der);
        }
        Ok(output)
    }

    pub(super) fn decode(input: &[u8]) -> anyhow::Result<Self> {
        let mut cursor = Cursor::new(input);
        ensure!(
            cursor.take(MAGIC.len())? == MAGIC,
            "invalid Coauth key-bundle magic"
        );
        ensure!(
            cursor.u16()? == FORMAT_VERSION,
            "unsupported Coauth key-bundle format version"
        );
        let mut encryption_key = [0u8; 32];
        encryption_key.copy_from_slice(cursor.take(32)?);
        let key_count = usize::from(cursor.u16()?);
        ensure!(
            (1..=MAX_KEY_COUNT).contains(&key_count),
            "Coauth key bundle must contain between 1 and {MAX_KEY_COUNT} keys (got {key_count})"
        );
        let mut keys = Vec::with_capacity(key_count);
        for _ in 0..key_count {
            let kid_len = usize::from(cursor.u16()?);
            let kid = if kid_len == 0 {
                None
            } else {
                Some(
                    std::str::from_utf8(cursor.take(kid_len)?)
                        .context("stored key id is not UTF-8")?
                        .to_owned(),
                )
            };
            let der_len = usize::try_from(cursor.u32()?).context("invalid private-key length")?;
            ensure!(der_len > 0, "stored private key must not be empty");
            keys.push(StoredKey {
                kid,
                der: Zeroizing::new(cursor.take(der_len)?.to_vec()),
            });
        }
        ensure!(
            cursor.remaining() == 0,
            "trailing bytes in Coauth key bundle"
        );
        Ok(Self {
            encryption_key: Zeroizing::new(encryption_key),
            keys,
        })
    }
}

pub(super) async fn generate_key_bundle<R>(rng: &mut R) -> anyhow::Result<StoredKeyBundle>
where
    R: RngCore + Send,
{
    let rsa_key = {
        let key_rng = rand_chacha::ChaChaRng::from_rng(&mut *rng)?;
        task::spawn_blocking(move || PrivateKey::generate_rsa(key_rng))
            .await
            .context("joining RSA key-generation task")??
    };
    let ec_p256_key = spawn_keygen(rng, PrivateKey::generate_ec_p256).await?;
    let ec_p384_key = spawn_keygen(rng, PrivateKey::generate_ec_p384).await?;
    let ec_p521_key = spawn_keygen(rng, PrivateKey::generate_ec_p521).await?;
    let ec_k256_key = spawn_keygen(rng, PrivateKey::generate_ec_k256).await?;
    let account_authority_key = spawn_keygen(rng, PrivateKey::generate_ed25519).await?;
    let audit_signing_key = spawn_keygen(rng, PrivateKey::generate_ed25519).await?;
    let session_grant_key = spawn_keygen(rng, PrivateKey::generate_ed25519).await?;

    let mut encryption_key = [0u8; 32];
    rng.fill_bytes(&mut encryption_key);
    let keys = vec![
        stored_key(rsa_key, None)?,
        stored_key(ec_p256_key, None)?,
        stored_key(ec_p384_key, None)?,
        stored_key(ec_p521_key, None)?,
        stored_key(ec_k256_key, None)?,
        stored_key(
            account_authority_key,
            Some(coauth_keyring::ACCOUNT_AUTHORITY_KEY_ID),
        )?,
        stored_key(
            audit_signing_key,
            Some(coauth_keyring::AUDIT_SIGNING_KEY_ID),
        )?,
        stored_key(
            session_grant_key,
            Some(coauth_keyring::SESSION_GRANT_SIGNING_KEY_ID),
        )?,
    ];
    debug_assert_eq!(keys.len(), INITIAL_KEY_COUNT);
    Ok(StoredKeyBundle {
        encryption_key: Zeroizing::new(encryption_key),
        keys,
    })
}

async fn spawn_keygen<R, F>(rng: &mut R, generate: F) -> anyhow::Result<PrivateKey>
where
    R: RngCore,
    F: FnOnce(rand_chacha::ChaChaRng) -> PrivateKey + Send + 'static,
{
    let key_rng = rand_chacha::ChaChaRng::from_rng(rng)?;
    task::spawn_blocking(move || generate(key_rng))
        .await
        .context("joining private-key generation task")
}

fn stored_key(key: PrivateKey, kid: Option<&str>) -> anyhow::Result<StoredKey> {
    Ok(StoredKey {
        kid: kid.map(str::to_owned),
        der: key
            .to_pkcs8_der()
            .context("encoding generated private key")?,
    })
}

struct Cursor<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    fn take(&mut self, length: usize) -> anyhow::Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or_else(|| anyhow::anyhow!("key-bundle length overflow"))?;
        let value = self
            .input
            .get(self.offset..end)
            .ok_or_else(|| anyhow::anyhow!("truncated Coauth key bundle"))?;
        self.offset = end;
        Ok(value)
    }

    fn u16(&mut self) -> anyhow::Result<u16> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().map_err(
            |_| anyhow::anyhow!("invalid u16 in key bundle"),
        )?))
    }

    fn u32(&mut self) -> anyhow::Result<u32> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().map_err(
            |_| anyhow::anyhow!("invalid u32 in key bundle"),
        )?))
    }

    const fn remaining(&self) -> usize {
        self.input.len() - self.offset
    }
}

#[cfg(test)]
mod tests {
    use rand_core::SeedableRng;

    use super::*;

    #[tokio::test]
    async fn binary_bundle_round_trips_and_rejects_trailing_data() {
        let mut rng = rand_chacha::ChaChaRng::from_seed([4; 32]);
        let bundle = generate_key_bundle(&mut rng).await.unwrap();
        let encoded = bundle.encode().unwrap();
        let decoded = StoredKeyBundle::decode(&encoded).unwrap();
        assert_eq!(decoded.keys.len(), INITIAL_KEY_COUNT);
        assert_eq!(
            decoded.encryption_key.as_ref(),
            bundle.encryption_key.as_ref()
        );

        let mut trailing = encoded.to_vec();
        trailing.push(0);
        assert!(StoredKeyBundle::decode(&trailing).is_err());
    }

    #[test]
    fn binary_bundle_rejects_wrong_magic() {
        let mut invalid = vec![0; 44];
        invalid[..8].copy_from_slice(b"INVALID!");
        let error = StoredKeyBundle::decode(&invalid).err().unwrap();
        assert!(error.to_string().contains("magic"));
    }
}
