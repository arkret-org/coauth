// Copyright 2025 Taidge contributors
//
// SPDX-License-Identifier: Apache-2.0

//! CLI sub-command for validating and optionally rendering templates.

use std::fmt::Write as _;
use std::process::ExitCode;

use anyhow::{Context as _, bail};
use camino::Utf8PathBuf;
use chrono::DateTime;
use clap::Parser;
use coauth_backend::util::{site_config_from_config, templates_from_config};
use coauth_config::{
    AccountConfig, BrandingConfig, CaptchaConfig, ConfigurationSectionExt, ExperimentalConfig,
    HttpConfig, PasswordsConfig, SmsConfig, TemplatesConfig,
};
use coauth_data::{Clock, SystemClock};
use figment::Figment;
use rand_core::SeedableRng;
use tracing::info_span;

/// Top-level options for the `templates` command.
#[derive(Parser, Debug)]
pub(super) struct Options {
    #[clap(subcommand)]
    subcommand: Subcommand,
}

#[derive(Parser, Debug)]
enum Subcommand {
    /// Validate the configured templates and optionally render them to disk.
    Check {
        /// Directory to write rendered templates into. Must be empty or
        /// non-existent.
        #[arg(long = "out-dir")]
        out_dir: Option<Utf8PathBuf>,

        /// Pin non-deterministic inputs (timestamps, asset hashes) to fixed
        /// values so successive renders can be diffed.
        #[arg(long = "stabilise")]
        stabilise: bool,
    },
}

impl Options {
    pub async fn run(self, figment: &Figment) -> anyhow::Result<ExitCode> {
        let Subcommand::Check { out_dir, stabilise } = self.subcommand;

        let _span = info_span!("cli.templates.check").entered();

        // ── Load every config section the renderer needs ─────────────
        let tpl_cfg =
            TemplatesConfig::extract_or_default(figment).map_err(anyhow::Error::from_boxed)?;
        let brand_cfg =
            BrandingConfig::extract_or_default(figment).map_err(anyhow::Error::from_boxed)?;
        let http_cfg =
            HttpConfig::extract_or_default(figment).map_err(anyhow::Error::from_boxed)?;
        let exp_cfg =
            ExperimentalConfig::extract_or_default(figment).map_err(anyhow::Error::from_boxed)?;
        let pw_cfg =
            PasswordsConfig::extract_or_default(figment).map_err(anyhow::Error::from_boxed)?;
        let acct_cfg =
            AccountConfig::extract_or_default(figment).map_err(anyhow::Error::from_boxed)?;
        let captcha_cfg =
            CaptchaConfig::extract_or_default(figment).map_err(anyhow::Error::from_boxed)?;
        let sms_cfg = SmsConfig::extract_or_default(figment).map_err(anyhow::Error::from_boxed)?;

        // ── Deterministic clock / RNG when stabilising ───────────────
        let now = if stabilise {
            DateTime::from_timestamp_secs(1_446_823_992).unwrap()
        } else {
            SystemClock::default().now()
        };

        let rng = if stabilise {
            rand_chacha::ChaChaRng::from_seed([42; 32])
        } else {
            rand_chacha::ChaChaRng::from_entropy()
        };

        // ── Build renderer ───────────────────────────────────────────
        let url_builder = coauth_data::UrlBuilder::new("https://example.com/".parse()?, None, None);

        let site_config = site_config_from_config(
            &brand_cfg,
            &http_cfg,
            &exp_cfg,
            &pw_cfg,
            &acct_cfg,
            &captcha_cfg,
            &sms_cfg,
        )?;

        let templates = templates_from_config(
            &tpl_cfg,
            &site_config,
            &url_builder,
            true, // strict mode
        )
        .await?;

        let rendered = templates.check_render(now, &rng)?;

        // ── Optionally persist to disk ───────────────────────────────
        if let Some(dir) = out_dir {
            ensure_dir_empty_or_create(&dir).await?;

            for ((name, sample), html) in &rendered {
                let (stem, ext) = name.rsplit_once('.').unwrap_or((name, "txt"));
                let stem = stem.replace('/', "_");

                let mut suffix = String::new();
                for (k, v) in &sample.components {
                    write!(suffix, "-{k}={v}")?;
                }

                let path = dir.join(format!("{stem}{suffix}.{ext}"));
                tokio::fs::write(&path, html.as_bytes())
                    .await
                    .with_context(|| format!("failed to write {path}"))?;
            }
        }

        Ok(ExitCode::SUCCESS)
    }
}

/// Create the directory if absent, or verify it is empty.
async fn ensure_dir_empty_or_create(dir: &Utf8PathBuf) -> anyhow::Result<()> {
    if dir.exists() {
        let mut rd = tokio::fs::read_dir(dir)
            .await
            .with_context(|| format!("cannot read {dir}"))?;
        if rd.next_entry().await?.is_some() {
            bail!("{dir} is not empty; refusing to overwrite");
        }
    } else {
        tokio::fs::create_dir(dir)
            .await
            .with_context(|| format!("cannot create {dir}"))?;
    }
    Ok(())
}
