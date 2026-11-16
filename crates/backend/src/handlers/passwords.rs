// Copyright 2024, 2025 Taidge Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use pbkdf2::Pbkdf2;
use rand_core::{CryptoRng, RngCore, SeedableRng};
use thiserror::Error;
use zeroize::Zeroizing;
use zxcvbn::zxcvbn;

pub type SchemeVersion = u16;

/// Outcome of verifying a password against its stored hash.
#[must_use]
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum PasswordVerificationResult {
    /// The supplied password matched.
    Matched,
    /// The supplied password did not match.
    NotMatched,
}

impl PasswordVerificationResult {
    fn matched() -> Self {
        Self::Matched
    }

    fn not_matched() -> Self {
        Self::NotMatched
    }
}

impl PasswordVerificationResult {
    #[must_use]
    pub fn is_success(&self) -> bool {
        matches!(self, Self::Matched)
    }
}

impl From<bool> for PasswordVerificationResult {
    fn from(ok: bool) -> Self {
        if ok {
            Self::matched()
        } else {
            Self::not_matched()
        }
    }
}

#[derive(Debug, Error)]
#[error("Password manager is disabled")]
pub struct PasswordManagerDisabledError;

#[derive(Clone)]
pub struct PasswordManager {
    inner: Option<Arc<InnerPasswordManager>>,
}

struct InnerPasswordManager {
    /// Minimum complexity score of new passwords (between 0 and 4) as evaluated
    /// by zxcvbn.
    minimum_complexity: u8,
    current_hasher: Hasher,
}

impl PasswordManager {
    /// Creates a password manager with one active hasher and complexity score.
    #[must_use]
    pub fn new(minimum_complexity: u8, hasher: Hasher) -> Self {
        Self {
            inner: Some(Arc::new(InnerPasswordManager {
                minimum_complexity,
                current_hasher: hasher,
            })),
        }
    }

    /// Creates a new disabled password manager
    #[must_use]
    pub const fn disabled() -> Self {
        Self { inner: None }
    }

    /// Checks if the password manager is enabled or not
    #[must_use]
    pub const fn is_enabled(&self) -> bool {
        self.inner.is_some()
    }

    /// Get the inner password manager
    ///
    /// # Errors
    ///
    /// Returns an error if the password manager is disabled
    fn get_inner(&self) -> Result<Arc<InnerPasswordManager>, PasswordManagerDisabledError> {
        self.inner.clone().ok_or(PasswordManagerDisabledError)
    }

    /// Returns true if and only if the given password satisfies the minimum
    /// complexity requirements.
    ///
    /// # Errors
    ///
    /// Returns an error if the password manager is disabled
    pub fn is_password_complex_enough(
        &self,
        password: &str,
    ) -> Result<bool, PasswordManagerDisabledError> {
        let inner = self.get_inner()?;
        let score = zxcvbn(password, &[]);
        Ok(u8::from(score.score()) >= inner.minimum_complexity)
    }

    /// Run a dummy hash with the supplied password to produce timing
    /// equivalent to a real [`PasswordManager::verify`] call against the
    /// current scheme.
    ///
    /// Use this on login paths where the username is unknown or has no
    /// active password, so attackers cannot use response latency to
    /// distinguish "user exists but bad password" from "no such user".
    /// The hash output is discarded.
    ///
    /// Silently returns `Ok(())` if the password manager is disabled, so
    /// the caller does not need to special-case that path.
    #[tracing::instrument(name = "passwords.dummy_verify", skip_all)]
    pub async fn dummy_verify<R: CryptoRng + RngCore + Send>(
        &self,
        rng: R,
        password: Zeroizing<String>,
    ) -> Result<(), anyhow::Error> {
        let Some(inner) = self.inner.clone() else {
            return Ok(());
        };

        // Seed a future-local RNG so the RNG passed in parameters doesn't have to be
        // 'static
        let rng = rand_chacha::ChaChaRng::from_rng(rng)?;
        let span = tracing::Span::current();

        tokio::task::spawn_blocking(move || {
            span.in_scope(move || inner.current_hasher.hash_blocking(rng, password))
        })
        .await??;

        Ok(())
    }

    /// Hash a password with the default hashing scheme.
    /// Returns the version of the hashing scheme used and the hashed password.
    ///
    /// # Errors
    ///
    /// Returns an error if the hashing failed or if the password manager is
    /// disabled
    #[tracing::instrument(name = "passwords.hash", skip_all)]
    pub async fn hash<R: CryptoRng + RngCore + Send>(
        &self,
        rng: R,
        password: Zeroizing<String>,
    ) -> Result<(SchemeVersion, String), anyhow::Error> {
        let inner = self.get_inner()?;

        // Seed a future-local RNG so the RNG passed in parameters doesn't have to be
        // 'static
        let rng = rand_chacha::ChaChaRng::from_rng(rng)?;
        let span = tracing::Span::current();

        let hashed = tokio::task::spawn_blocking(move || {
            span.in_scope(move || inner.current_hasher.hash_blocking(rng, password))
        })
        .await??;

        Ok((1, hashed))
    }

    /// Verify a password hash for the given hashing scheme.
    ///
    /// # Errors
    ///
    /// Returns an error if the password hash verification failed or if the
    /// password manager is disabled
    #[tracing::instrument(name = "passwords.verify", skip_all, fields(%scheme))]
    pub async fn verify(
        &self,
        scheme: SchemeVersion,
        password: Zeroizing<String>,
        hashed_password: String,
    ) -> Result<PasswordVerificationResult, anyhow::Error> {
        let inner = self.get_inner()?;
        let span = tracing::Span::current();

        let outcome = tokio::task::spawn_blocking(move || {
            span.in_scope(move || {
                anyhow::ensure!(scheme == 1, "Password hash must use the current v1 scheme");
                inner
                    .current_hasher
                    .verify_blocking(&hashed_password, password)
            })
        })
        .await??;

        Ok(outcome)
    }
}

/// A hashing scheme, with an optional pepper
pub struct Hasher {
    algorithm: Algorithm,
    /// Optional pepper mixed into the password hash.
    pepper: Option<Vec<u8>>,
}

impl Hasher {
    /// Creates a new hashing scheme based on the bcrypt algorithm
    #[must_use]
    pub const fn bcrypt(cost: Option<u32>, pepper: Option<Vec<u8>>) -> Self {
        let algorithm = Algorithm::Bcrypt { cost };
        Self { algorithm, pepper }
    }

    /// Creates a new hashing scheme based on the argon2id algorithm
    #[must_use]
    pub const fn argon2id(pepper: Option<Vec<u8>>) -> Self {
        let algorithm = Algorithm::Argon2id;
        Self { algorithm, pepper }
    }

    /// Creates a new hashing scheme based on the pbkdf2 algorithm
    #[must_use]
    pub const fn pbkdf2(pepper: Option<Vec<u8>>) -> Self {
        let algorithm = Algorithm::Pbkdf2;
        Self { algorithm, pepper }
    }

    fn hash_blocking<R: CryptoRng + RngCore>(
        &self,
        rng: R,
        password: Zeroizing<String>,
    ) -> Result<String, anyhow::Error> {
        self.algorithm
            .hash_blocking(rng, password.as_bytes(), self.pepper.as_deref())
    }

    fn verify_blocking(
        &self,
        hashed_password: &str,
        password: Zeroizing<String>,
    ) -> Result<PasswordVerificationResult, anyhow::Error> {
        self.algorithm
            .verify_blocking(hashed_password, password.as_bytes(), self.pepper.as_deref())
    }
}

#[derive(Debug, Clone, Copy)]
enum Algorithm {
    Bcrypt { cost: Option<u32> },
    Argon2id,
    Pbkdf2,
}

impl Algorithm {
    fn hash_blocking<R: CryptoRng + RngCore>(
        self,
        mut rng: R,
        password: &[u8],
        pepper: Option<&[u8]>,
    ) -> Result<String, anyhow::Error> {
        match self {
            Self::Bcrypt { cost } => {
                let mut password = Zeroizing::new(password.to_vec());
                if let Some(pepper) = pepper {
                    password.extend_from_slice(pepper);
                }

                let mut salt = [0u8; 16];
                rng.fill_bytes(&mut salt);

                let hashed = bcrypt::hash_with_salt(password, cost.unwrap_or(12), salt)?;
                Ok(hashed.format_for_version(bcrypt::Version::TwoB))
            }

            Self::Argon2id => {
                let algorithm = argon2::Algorithm::default();
                let version = argon2::Version::default();
                let parameters = argon2::Params::default();

                let phf = if let Some(secret) = pepper {
                    Argon2::new_with_secret(secret, algorithm, version, parameters)?
                } else {
                    Argon2::new(algorithm, version, parameters)
                };

                let salt = SaltString::generate(rng);
                let hashed = phf.hash_password(password.as_ref(), &salt)?;
                Ok(hashed.to_string())
            }

            Self::Pbkdf2 => {
                let mut password = Zeroizing::new(password.to_vec());
                if let Some(pepper) = pepper {
                    password.extend_from_slice(pepper);
                }

                let salt = SaltString::generate(rng);
                let hashed = Pbkdf2.hash_password(password.as_ref(), &salt)?;
                Ok(hashed.to_string())
            }
        }
    }

    fn verify_blocking(
        self,
        hashed_password: &str,
        password: &[u8],
        pepper: Option<&[u8]>,
    ) -> Result<PasswordVerificationResult, anyhow::Error> {
        let outcome = match self {
            Algorithm::Bcrypt { .. } => {
                let mut password = Zeroizing::new(password.to_vec());
                if let Some(pepper) = pepper {
                    password.extend_from_slice(pepper);
                }

                let ok = bcrypt::verify(password, hashed_password)?;
                PasswordVerificationResult::from(ok)
            }

            Algorithm::Argon2id => {
                let algorithm = argon2::Algorithm::default();
                let version = argon2::Version::default();
                let parameters = argon2::Params::default();

                let phf = if let Some(secret) = pepper {
                    Argon2::new_with_secret(secret, algorithm, version, parameters)?
                } else {
                    Argon2::new(algorithm, version, parameters)
                };

                let parsed = PasswordHash::new(hashed_password)?;

                match phf.verify_password(password.as_ref(), &parsed) {
                    Ok(()) => PasswordVerificationResult::matched(),
                    Err(argon2::password_hash::Error::Password) => {
                        PasswordVerificationResult::not_matched()
                    }
                    Err(e) => return Err(e.into()),
                }
            }

            Algorithm::Pbkdf2 => {
                let mut password = Zeroizing::new(password.to_vec());
                if let Some(pepper) = pepper {
                    password.extend_from_slice(pepper);
                }

                let parsed = PasswordHash::new(hashed_password)?;

                match Pbkdf2.verify_password(password.as_ref(), &parsed) {
                    Ok(()) => PasswordVerificationResult::matched(),
                    Err(pbkdf2::password_hash::Error::Password) => {
                        PasswordVerificationResult::not_matched()
                    }
                    Err(e) => return Err(e.into()),
                }
            }
        };

        Ok(outcome)
    }
}

#[cfg(test)]
mod tests {
    use rand_core::SeedableRng;

    use super::*;

    #[test]
    fn hashing_bcrypt() {
        let mut rng = rand_chacha::ChaChaRng::seed_from_u64(42);
        let password = b"hunter2";
        let password2 = b"wrong-password";
        let pepper = b"a-secret-pepper";
        let pepper2 = b"the-wrong-pepper";

        let alg = Algorithm::Bcrypt { cost: Some(10) };
        // Hash with a pepper
        let hash = alg
            .hash_blocking(&mut rng, password, Some(pepper))
            .expect("Couldn't hash password");
        insta::assert_snapshot!(hash);

        assert_eq!(
            alg.verify_blocking(&hash, password, Some(pepper))
                .expect("Verification failed"),
            PasswordVerificationResult::Matched
        );
        assert_eq!(
            alg.verify_blocking(&hash, password2, Some(pepper))
                .expect("Verification failed"),
            PasswordVerificationResult::NotMatched
        );
        assert_eq!(
            alg.verify_blocking(&hash, password, Some(pepper2))
                .expect("Verification failed"),
            PasswordVerificationResult::NotMatched
        );
        assert_eq!(
            alg.verify_blocking(&hash, password, None)
                .expect("Verification failed"),
            PasswordVerificationResult::NotMatched
        );

        // Hash without pepper
        let hash = alg
            .hash_blocking(&mut rng, password, None)
            .expect("Couldn't hash password");
        insta::assert_snapshot!(hash);

        assert_eq!(
            alg.verify_blocking(&hash, password, None)
                .expect("Verification failed"),
            PasswordVerificationResult::Matched
        );
        assert_eq!(
            alg.verify_blocking(&hash, password2, None)
                .expect("Verification failed"),
            PasswordVerificationResult::NotMatched
        );
        assert_eq!(
            alg.verify_blocking(&hash, password, Some(pepper))
                .expect("Verification failed"),
            PasswordVerificationResult::NotMatched
        );
    }

    #[test]
    fn hashing_argon2id() {
        let mut rng = rand_chacha::ChaChaRng::seed_from_u64(42);
        let password = b"hunter2";
        let password2 = b"wrong-password";
        let pepper = b"a-secret-pepper";
        let pepper2 = b"the-wrong-pepper";

        let alg = Algorithm::Argon2id;
        // Hash with a pepper
        let hash = alg
            .hash_blocking(&mut rng, password, Some(pepper))
            .expect("Couldn't hash password");
        insta::assert_snapshot!(hash);

        assert_eq!(
            alg.verify_blocking(&hash, password, Some(pepper))
                .expect("Verification failed"),
            PasswordVerificationResult::Matched
        );
        assert_eq!(
            alg.verify_blocking(&hash, password2, Some(pepper))
                .expect("Verification failed"),
            PasswordVerificationResult::NotMatched
        );
        assert_eq!(
            alg.verify_blocking(&hash, password, Some(pepper2))
                .expect("Verification failed"),
            PasswordVerificationResult::NotMatched
        );
        assert_eq!(
            alg.verify_blocking(&hash, password, None)
                .expect("Verification failed"),
            PasswordVerificationResult::NotMatched
        );

        // Hash without pepper
        let hash = alg
            .hash_blocking(&mut rng, password, None)
            .expect("Couldn't hash password");
        insta::assert_snapshot!(hash);

        assert_eq!(
            alg.verify_blocking(&hash, password, None)
                .expect("Verification failed"),
            PasswordVerificationResult::Matched
        );
        assert_eq!(
            alg.verify_blocking(&hash, password2, None)
                .expect("Verification failed"),
            PasswordVerificationResult::NotMatched
        );
        assert_eq!(
            alg.verify_blocking(&hash, password, Some(pepper))
                .expect("Verification failed"),
            PasswordVerificationResult::NotMatched
        );
    }

    #[test]
    fn hashing_pbkdf2() {
        let mut rng = rand_chacha::ChaChaRng::seed_from_u64(42);
        let password = b"hunter2";
        let password2 = b"wrong-password";
        let pepper = b"a-secret-pepper";
        let pepper2 = b"the-wrong-pepper";

        let alg = Algorithm::Pbkdf2;
        // Hash with a pepper
        let hash = alg
            .hash_blocking(&mut rng, password, Some(pepper))
            .expect("Couldn't hash password");
        insta::assert_snapshot!(hash);

        assert_eq!(
            alg.verify_blocking(&hash, password, Some(pepper))
                .expect("Verification failed"),
            PasswordVerificationResult::Matched
        );
        assert_eq!(
            alg.verify_blocking(&hash, password2, Some(pepper))
                .expect("Verification failed"),
            PasswordVerificationResult::NotMatched
        );
        assert_eq!(
            alg.verify_blocking(&hash, password, Some(pepper2))
                .expect("Verification failed"),
            PasswordVerificationResult::NotMatched
        );
        assert_eq!(
            alg.verify_blocking(&hash, password, None)
                .expect("Verification failed"),
            PasswordVerificationResult::NotMatched
        );

        // Hash without pepper
        let hash = alg
            .hash_blocking(&mut rng, password, None)
            .expect("Couldn't hash password");
        insta::assert_snapshot!(hash);

        assert_eq!(
            alg.verify_blocking(&hash, password, None)
                .expect("Verification failed"),
            PasswordVerificationResult::Matched
        );
        assert_eq!(
            alg.verify_blocking(&hash, password2, None)
                .expect("Verification failed"),
            PasswordVerificationResult::NotMatched
        );
        assert_eq!(
            alg.verify_blocking(&hash, password, Some(pepper))
                .expect("Verification failed"),
            PasswordVerificationResult::NotMatched
        );
    }

    #[tokio::test]
    async fn dummy_verify_succeeds_and_is_disabled_safe() {
        let mut rng = rand_chacha::ChaChaRng::seed_from_u64(7);
        let password = Zeroizing::new("hunter2".to_owned());

        let manager = PasswordManager::new(0, Hasher::argon2id(None));
        manager
            .dummy_verify(&mut rng, password.clone())
            .await
            .expect("dummy verify should succeed when enabled");

        let disabled = PasswordManager::disabled();
        disabled
            .dummy_verify(&mut rng, password)
            .await
            .expect("dummy verify on a disabled manager is a no-op");
    }

    #[tokio::test]
    async fn active_scheme_verifies_password_and_rejects_unknown_tag() {
        let mut rng = rand_chacha::ChaChaRng::seed_from_u64(42);
        let password = Zeroizing::new("hunter2".to_owned());
        for hasher in [
            Hasher::argon2id(None),
            Hasher::bcrypt(Some(10), Some(b"a-secret-pepper".to_vec())),
            Hasher::pbkdf2(None),
        ] {
            let manager = PasswordManager::new(0, hasher);
            let (version, hash) = manager.hash(&mut rng, password.clone()).await.unwrap();
            assert_eq!(version, 1);
            assert_eq!(
                manager
                    .verify(version, password.clone(), hash.clone())
                    .await
                    .unwrap(),
                PasswordVerificationResult::Matched
            );
            assert_eq!(
                manager
                    .verify(
                        version,
                        Zeroizing::new("wrong-password".to_owned()),
                        hash.clone()
                    )
                    .await
                    .unwrap(),
                PasswordVerificationResult::NotMatched
            );
            manager
                .verify(2, password.clone(), hash)
                .await
                .expect_err("unknown scheme tag must fail closed");
        }
    }
}
