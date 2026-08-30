// Copyright (c) 2026 Arkret Authors. Licensed under the Apache License,
// Version 2.0; see LICENSE-APACHE for details.

// ── Secret and Key Configuration ──
//
// Manages cryptographic keys and encryption secrets used for signing,
// verifying, and encrypting application payloads and cookies.

mod encryption;
mod generation;
mod key_config;

use anyhow::Context;
use camino::Utf8PathBuf;
use coauth_jose::jwk::JsonWebKeySet;
use coauth_keystore::{Encrypter, Keystore};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use self::encryption::{EncryptionKey, EncryptionKeyRaw};
use self::key_config::{KeyConfig, enumerate_keys_in_directory};
use super::ConfigurationSection;

// ── Secrets Section ──

/// Aggregates all cryptographic material: signing keys, encryption keys,
/// and optional key directories
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SecretsConfig {
    /// Encryption key for secure cookies
    #[schemars(with = "EncryptionKeyRaw")]
    #[serde_as(as = "serde_with::TryFromInto<EncryptionKeyRaw>")]
    #[serde(flatten)]
    encryption: EncryptionKey,

    /// List of private keys to use for signing and encrypting payloads.
    #[serde(skip_serializing_if = "Option::is_none")]
    keys: Option<Vec<KeyConfig>>,

    /// Directory of private keys to use for signing and encrypting payloads.
    #[schemars(with = "Option<String>")]
    #[serde(skip_serializing_if = "Option::is_none")]
    keys_dir: Option<Utf8PathBuf>,
}

impl ConfigurationSection for SecretsConfig {
    const PATH: &'static str = "secrets";
}

impl SecretsConfig {
    // ── Public API ──

    /// Builds a signing/verifying [`Keystore`] from the configured keys.
    ///
    /// # Errors
    ///
    /// Returns an error when a key could not be loaded or parsed.
    #[tracing::instrument(name = "secrets.load", skip_all)]
    pub async fn key_store(&self) -> anyhow::Result<Keystore> {
        let all_keys = self.collect_key_configs().await?;
        let mut jwk_list = Vec::with_capacity(all_keys.len());
        for key in &all_keys {
            let source = key.source_description();
            let jwk = key
                .to_json_web_key()
                .await
                .with_context(|| format!("loading {source}"))?;
            jwk_list.push(jwk);
        }
        let jwk_set =
            JsonWebKeySet::try_new(jwk_list).context("invalid JWK metadata in secrets config")?;
        Ok(Keystore::new(jwk_set))
    }

    /// Derive an [`Encrypter`] from the configured encryption key.
    ///
    /// # Errors
    ///
    /// Returns an error when the encryption key cannot be resolved.
    pub async fn encrypter(&self) -> anyhow::Result<Encrypter> {
        self.encryption.to_encrypter().await
    }

    /// Returns the raw 32-byte encryption secret.
    ///
    /// # Errors
    ///
    /// Returns an error when the encryption secret could not be read from file.
    pub async fn encryption(&self) -> anyhow::Result<[u8; 32]> {
        self.encryption.resolve().await
    }

    // ── Internal helpers ──

    /// Merges directory-sourced and inline key configs into a unified list
    async fn collect_key_configs(&self) -> anyhow::Result<Vec<KeyConfig>> {
        let mut combined = match &self.keys_dir {
            Some(dir) => enumerate_keys_in_directory(dir).await?,
            None => vec![],
        };

        let inline_keys = self.keys.as_deref().unwrap_or_default();
        combined.extend(inline_keys.iter().cloned());

        Ok(combined)
    }
}

// ── Tests ──

#[cfg(test)]
mod tests {
    #![allow(clippy::result_large_err)]
    use coauth_iana::jose::JsonWebSignatureAlg;
    use coauth_jose::constraints::Constrainable;
    use figment::providers::{Format, Yaml};
    use figment::{Figment, Jail};
    use rand_core::SeedableRng;
    use tokio::runtime::Handle;
    use tokio::task;

    use super::encryption::EncryptionKey;
    use super::key_config::Key;
    use super::*;

    #[tokio::test]
    async fn load_config() {
        task::spawn_blocking(|| {
            Jail::expect_with(|jail| {
                jail.create_file(
                    "config.yaml",
                    indoc::indoc! {r"
                        secrets:
                          encryption_file: encryption
                          keys_dir: keys
                    "},
                )?;
                jail.create_file(
                    "encryption",
                    "0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff",
                )?;
                jail.create_dir("keys")?;
                jail.create_file(
                    "keys/key1",
                    indoc::indoc! {r"
                        -----BEGIN RSA PRIVATE KEY-----
                        MIIJKQIBAAKCAgEA6oR6LXzJOziUxcRryonLTM5Xkfr9cYPCKvnwsWoAHfd2MC6Q
                        OCAWSQnNcNz5RTeQUcLEaA8sxQi64zpCwO9iH8y8COCaO8u9qGkOOuJwWnmPfeLs
                        cEwALEp0LZ67eSUPsMaz533bs4C8p+2UPMd+v7Td8TkkYoqgUrfYuT0bDTMYVsSe
                        wcNB5qsI7hDLf1t5FX6KU79/Asn1K3UYHTdN83mghOlM4zh1l1CJdtgaE1jAg4Ml
                        1X8yG+cT+Ks8gCSGQfIAlVFV4fvvzmpokNKfwAI/b3LS2/ft4ZrK+RCTsWsjUu38
                        Zr8jbQMtDznzBHMw1LoaHpwRNjbJZ7uA6x5ikbwz5NAlfCITTta6xYn8qvaBfiYJ
                        YyUFl0kIHm9Kh9V9p54WPMCFCcQx12deovKV82S6zxTeMflDdosJDB/uG9dT2qPt
                        wkpTD6xAOx5h59IhfiY0j4ScTl725GygVzyK378soP3LQ/vBixQLpheALViotodH
                        fJknsrelaISNkrnapZL3QE5C1SUoaUtMG9ovRz5HDpMx5ooElEklq7shFWDhZXbp
                        2ndU5RPRCZO3Szop/Xhn2mNWQoEontFh79WIf+wS8TkJIRXhjtYBt3+s96z0iqSg
                        gDmE8BcP4lP1+TAUY1d7+QEhGCsTJa9TYtfDtNNfuYI9e3mq6LEpHYKWOvECAwEA
                        AQKCAgAlF60HaCGf50lzT6eePQCAdnEtWrMeyDCRgZTLStvCjEhk7d3LssTeP9mp
                        oe8fPomUv6c3BOds2/5LQFockABHd/y/CV9RA973NclAEQlPlhiBrb793Vd4VJJe
                        6331dveDW0+ggVdFjfVzjhqQfnE9ZcsQ2JvjpiTI0Iv2cy7F01tke0GCSMgx8W1p
                        J2jjDOxwNOKGGoIT8S4roHVJnFy3nM4sbNtyDj+zHimP4uBE8m2zSgQAP60E8sia
                        3+Ki1flnkXJRgQWCHR9cg5dkXfFRz56JmcdgxAHGWX2vD9XRuFi5nitPc6iTw8PV
                        u7GvS3+MC0oO+1pRkTAhOGv3RDK3Uqmy2zrMUuWkEsz6TVId6gPl7+biRJcP+aER
                        plJkeC9J9nSizbQPwErGByzoHGLjADgBs9hwqYkPcN38b6jR5S/VDQ+RncCyI87h
                        s/0pIs/fNlfw4LtpBrolP6g++vo6KUufmE3kRNN9dN4lNOoKjUGkcmX6MGnwxiw6
                        NN/uEqf9+CKQele1XeUhRPNJc9Gv+3Ly5y/wEi6FjfVQmCK4hNrl3tvuZw+qkGbq
                        Au9Jhk7wV81An7fbhBRIXrwOY9AbOKNqUfY+wpKi5vyJFS1yzkFaYSTKTBspkuHW
                        pWbohO+KreREwaR5HOMK8tQMTLEAeE3taXGsQMJSJ15lRrLc7QKCAQEA68TV/R8O
                        C4p+vnGJyhcfDJt6+KBKWlroBy75BG7Dg7/rUXaj+MXcqHi+whRNXMqZchSwzUfS
                        B2WK/HrOBye8JLKDeA3B5TumJaF19vV7EY/nBF2QdRmI1r33Cp+RWUvAcjKa/v2u
                        KksV3btnJKXCu/stdAyTK7nU0on4qBzm5WZxuIJv6VMHLDNPFdCk+4gM8LuJ3ITU
                        l7XuZd4gXccPNj0VTeOYiMjIwxtNmE9RpCkTLm92Z7MI+htciGk1xvV0N4m1BXwA
                        7qhl1nBgVuJyux4dEYFIeQNhLpHozkEz913QK2gDAHL9pAeiUYJntq4p8HNvfHiQ
                        vE3wTzil3aUFnwKCAQEA/qQm1Nx5By6an5UunrOvltbTMjsZSDnWspSQbX//j6mL
                        2atQLe3y/Nr7E5SGZ1kFD9tgAHTuTGVqjvTqp5dBPw4uo146K2RJwuvaYUzNK26c
                        VoGfMfsI+/bfMfjFnEmGRARZdMr8cvhU+2m04hglsSnNGxsvvPdsiIbRaVDx+JvN
                        C5C281WlN0WeVd7zNTZkdyUARNXfCxBHQPuYkP5Mz2roZeYlJMWU04i8Cx0/SEuu
                        bhZQDaNTccSdPDFYcyDDlpqp+mN+U7m+yUPOkVpaxQiSYJZ+NOQsNcAVYfjzyY0E
                        /VP3s2GddjCJs0amf9SeW0LiMAHPgTp8vbMSRPVVbwKCAQEAmZsSd+llsys2TEmY
                        pivONN6PjbCRALE9foCiCLtJcmr1m4uaZRg0HScd0UB87rmoo2TLk9L5CYyksr4n
                        wQ2oTJhpgywjaYAlTVsWiiGBXv3MW1HCLijGuHHno+o2PmFWLpC93ufUMwXcZywT
                        lRLR/rs07+jJcbGO8OSnNpAt9sN5z+Zblz5a6/c5zVK0SpRnKehld2CrSXRkr8W6
                        fJ6WUJYXbTmdRXDbLBJ7yYHUBQolzxkboZBJhvmQnec9/DQq1YxIfhw+Vz8rqjxo
                        5/J9IWALPD5owz7qb/bsIITmoIFkgQMxAXfpvJaksEov3Bs4g8oRlpzOX4C/0j1s
                        Ay3irQKCAQEAwRJ/qufcEFkCvjsj1QsS+MC785shyUSpiE/izlO91xTLx+f/7EM9
                        +QCkXK1B1zyE/Qft24rNYDmJOQl0nkuuGfxL2mzImDv7PYMM2reb3PGKMoEnzoKz
                        xi/h/YbNdnm9BvdxSH/cN+QYs2Pr1X5Pneu+622KnbHQphfq0fqg7Upchwdb4Faw
                        5Z6wthVMvK0YMcppUMgEzOOz0w6xGEbowGAkA5cj1KTG+jjzs02ivNM9V5Utb5nF
                        3D4iphAYK3rNMfTlKsejciIlCX+TMVyb9EdSjU+uM7ZJ2xtgWx+i4NA+10GCT42V
                        EZct4TORbN0ukK2+yH2m8yoAiOks0gJemwKCAQAMGROGt8O4HfhpUdOq01J2qvQL
                        m5oUXX8w1I95XcoAwCqb+dIan8UbCyl/79lbqNpQlHbRy3wlXzWwH9aHKsfPlCvk
                        5dE1qrdMdQhLXwP109bRmTiScuU4zfFgHw3XgQhMFXxNp9pze197amLws0TyuBW3
                        fupS4kM5u6HKCeBYcw2WP5ukxf8jtn29tohLBiA2A7NYtml9xTer6BBP0DTh+QUn
                        IJL6jSpuCNxBPKIK7p6tZZ0nMBEdAWMxglYm0bmHpTSd3pgu3ltCkYtDlDcTIaF0
                        Q4k44lxUTZQYwtKUVQXBe4ZvaT/jIEMS7K5bsAy7URv/toaTaiEh1hguwSmf
                        -----END RSA PRIVATE KEY-----
                    "},
                )?;
                jail.create_file(
                    "keys/key2",
                    indoc::indoc! {r"
                        -----BEGIN EC PRIVATE KEY-----
                        MHcCAQEEIKlZz/GnH0idVH1PnAF4HQNwRafgBaE2tmyN1wjfdOQqoAoGCCqGSM49
                        AwEHoUQDQgAEHrgPeG+Mt8eahih1h4qaPjhl7jT25cdzBkg3dbVks6gBR2Rx4ug9
                        h27LAir5RqxByHvua2XsP46rSTChof78uw==
                        -----END EC PRIVATE KEY-----
                    "},
                )?;

                let config = Figment::new()
                    .merge(Yaml::file("config.yaml"))
                    .extract_inner::<SecretsConfig>("secrets")?;

                Handle::current().block_on(async move {
                    assert!(
                        matches!(config.encryption, EncryptionKey::File(ref p) if p == "encryption")
                    );
                    assert_eq!(
                        config.encryption().await.unwrap(),
                        [
                            0, 0, 17, 17, 34, 34, 51, 51, 68, 68, 85, 85, 102, 102, 119, 119, 136,
                            136, 153, 153, 170, 170, 187, 187, 204, 204, 221, 221, 238, 238, 255,
                            255
                        ]
                    );

                    let mut key_config = config.collect_key_configs().await.unwrap();
                    key_config.sort_by_key(|a| {
                        if let Key::File(p) = &a.key {
                            Some(p.clone())
                        } else {
                            None
                        }
                    });
                    let key_store = config.key_store().await.unwrap();

                    assert!(key_config[0].kid.is_none());
                    assert!(matches!(&key_config[0].key, Key::File(p) if p == "keys/key1"));
                    assert!(key_store.iter().any(|k| k.kid() == Some("xmgGCzGtQFmhEOP0YAqBt-oZyVauSVMXcf4kwcgGZLc")));
                    assert!(key_config[1].kid.is_none());
                    assert!(matches!(&key_config[1].key, Key::File(p) if p == "keys/key2"));
                    assert!(key_store.iter().any(|k| k.kid() == Some("ONUCn80fsiISFWKrVMEiirNVr-QEvi7uQI0QH9q9q4o")));
                });

                Ok(())
            });
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn load_config_inline_secrets() {
        task::spawn_blocking(|| {
            Jail::expect_with(|jail| {
                jail.create_file(
                    "config.yaml",
                    indoc::indoc! {r"
                        secrets:
                          encryption: >-
                            0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff
                          keys:
                            - kid: lekid0
                              key: |
                                -----BEGIN EC PRIVATE KEY-----
                                MHcCAQEEIOtZfDuXZr/NC0V3sisR4Chf7RZg6a2dpZesoXMlsPeRoAoGCCqGSM49
                                AwEHoUQDQgAECfpqx64lrR85MOhdMxNmIgmz8IfmM5VY9ICX9aoaArnD9FjgkBIl
                                fGmQWxxXDSWH6SQln9tROVZaduenJqDtDw==
                                -----END EC PRIVATE KEY-----
                            - key: |
                                -----BEGIN EC PRIVATE KEY-----
                                MHcCAQEEIKlZz/GnH0idVH1PnAF4HQNwRafgBaE2tmyN1wjfdOQqoAoGCCqGSM49
                                AwEHoUQDQgAEHrgPeG+Mt8eahih1h4qaPjhl7jT25cdzBkg3dbVks6gBR2Rx4ug9
                                h27LAir5RqxByHvua2XsP46rSTChof78uw==
                                -----END EC PRIVATE KEY-----
                    "},
                )?;

                let config = Figment::new()
                    .merge(Yaml::file("config.yaml"))
                    .extract_inner::<SecretsConfig>("secrets")?;

                Handle::current().block_on(async move {
                    assert_eq!(
                        config.encryption().await.unwrap(),
                        [
                            0, 0, 17, 17, 34, 34, 51, 51, 68, 68, 85, 85, 102, 102, 119, 119, 136,
                            136, 153, 153, 170, 170, 187, 187, 204, 204, 221, 221, 238, 238, 255,
                            255
                        ]
                    );

                    let key_store = config.key_store().await.unwrap();
                    assert!(key_store.iter().any(|k| k.kid() == Some("lekid0")));
                    assert!(key_store.iter().any(|k| k.kid() == Some("ONUCn80fsiISFWKrVMEiirNVr-QEvi7uQI0QH9q9q4o")));
                });

                Ok(())
            });
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn load_config_mixed_key_sources() {
        task::spawn_blocking(|| {
            Jail::expect_with(|jail| {
                jail.create_file(
                    "config.yaml",
                    indoc::indoc! {r"
                        secrets:
                          encryption_file: encryption
                          keys_dir: keys
                          keys:
                            - kid: lekid0
                              key: |
                                -----BEGIN EC PRIVATE KEY-----
                                MHcCAQEEIOtZfDuXZr/NC0V3sisR4Chf7RZg6a2dpZesoXMlsPeRoAoGCCqGSM49
                                AwEHoUQDQgAECfpqx64lrR85MOhdMxNmIgmz8IfmM5VY9ICX9aoaArnD9FjgkBIl
                                fGmQWxxXDSWH6SQln9tROVZaduenJqDtDw==
                                -----END EC PRIVATE KEY-----
                    "},
                )?;
                jail.create_dir("keys")?;
                jail.create_file(
                    "keys/key_from_file",
                    indoc::indoc! {r"
                        -----BEGIN EC PRIVATE KEY-----
                        MHcCAQEEIKlZz/GnH0idVH1PnAF4HQNwRafgBaE2tmyN1wjfdOQqoAoGCCqGSM49
                        AwEHoUQDQgAEHrgPeG+Mt8eahih1h4qaPjhl7jT25cdzBkg3dbVks6gBR2Rx4ug9
                        h27LAir5RqxByHvua2XsP46rSTChof78uw==
                        -----END EC PRIVATE KEY-----
                    "},
                )?;

                let config = Figment::new()
                    .merge(Yaml::file("config.yaml"))
                    .extract_inner::<SecretsConfig>("secrets")?;

                Handle::current().block_on(async move {
                    let key_config = config.collect_key_configs().await.unwrap();
                    let key_store = config.key_store().await.unwrap();

                    assert!(key_config[0].kid.is_none());
                    assert!(matches!(&key_config[0].key, Key::File(p) if p == "keys/key_from_file"));
                    assert!(key_store.iter().any(|k| k.kid() == Some("ONUCn80fsiISFWKrVMEiirNVr-QEvi7uQI0QH9q9q4o")));
                    assert!(key_store.iter().any(|k| k.kid() == Some("lekid0")));
                });

                Ok(())
            });
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn generate_config_includes_extended_signing_keys() {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(42);
        let config = SecretsConfig::generate(&mut rng).await.unwrap();
        let key_store = config.key_store().await.unwrap();
        let algs = key_store.available_signing_algorithms();

        assert!(algs.contains(&JsonWebSignatureAlg::Es512));
        assert!(algs.contains(&JsonWebSignatureAlg::Ed25519));
        assert!(key_store.account_authority_seed().is_ok());
        assert!(
            key_store
                .iter()
                .any(|key| key.kid() == Some(coauth_keystore::ACCOUNT_AUTHORITY_KEY_ID))
        );
    }

    #[tokio::test]
    async fn key_store_reports_missing_key_file_path() {
        task::spawn_blocking(|| {
            Jail::expect_with(|jail| {
                jail.create_file(
                    "config.yaml",
                    indoc::indoc! {r"
                        secrets:
                          encryption: >-
                            0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff
                          keys:
                            - kid: missing-file
                              key_file: missing-key.pem
                    "},
                )?;

                let config = Figment::new()
                    .merge(Yaml::file("config.yaml"))
                    .extract_inner::<SecretsConfig>("secrets")?;

                Handle::current().block_on(async move {
                    let error = match config.key_store().await {
                        Ok(_) => panic!("expected missing key file to fail"),
                        Err(error) => format!("{error:#}"),
                    };
                    assert!(
                        error.contains(
                            "loading secrets key file missing-key.pem (kid=missing-file)"
                        )
                    );
                    assert!(error.contains("reading secrets key file missing-key.pem"));
                });

                Ok(())
            });
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn key_store_reports_inline_key_identity() {
        task::spawn_blocking(|| {
            Jail::expect_with(|jail| {
                jail.create_file(
                    "config.yaml",
                    indoc::indoc! {r"
                        secrets:
                          encryption: >-
                            0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff
                          keys:
                            - kid: broken-inline
                              key: |
                                not a private key
                    "},
                )?;

                let config = Figment::new()
                    .merge(Yaml::file("config.yaml"))
                    .extract_inner::<SecretsConfig>("secrets")?;

                Handle::current().block_on(async move {
                    let error = match config.key_store().await {
                        Ok(_) => panic!("expected invalid inline key to fail"),
                        Err(error) => format!("{error:#}"),
                    };
                    assert!(error.contains("loading inline secrets key (kid=broken-inline)"));
                });

                Ok(())
            });
        })
        .await
        .unwrap();
    }
}
