//! coauth CLI -- entry point for the Contrix Auth/Account Server binary.
//!
//! Provides sub-commands for the HTTP server, background worker, user
//! management, database operations, and diagnostics.
//!
//! Backend and server infrastructure live in the `coauth-backend` crate.

#![allow(clippy::module_name_repetitions)]

use std::{io::IsTerminal, process::ExitCode, sync::Arc};

use anyhow::Context;
use clap::Parser;
use coauth_config::{ConfigurationSectionExt, MetricsExporterKind, TelemetryConfig};
use sentry_tracing::EventFilter;
use tracing_subscriber::{
    EnvFilter, Layer, Registry,
    filter::{LevelFilter, filter_fn},
    layer::SubscriberExt,
    util::SubscriberInitExt,
};

mod commands;

/// Application version reported by `git describe` at build time
static VERSION: &str = env!("VERGEN_GIT_DESCRIBE");

// ---------------------------------------------------------------------------
// Sentry transport adapter
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct SentryTransportAdapter {
    http: reqwest::Client,
}

impl SentryTransportAdapter {
    fn create() -> Self {
        Self {
            http: coauth_backend::reqwest_client(),
        }
    }
}

impl sentry::TransportFactory for SentryTransportAdapter {
    fn create_transport(&self, opts: &sentry::ClientOptions) -> Arc<dyn sentry::Transport> {
        let inner = sentry::transports::ReqwestHttpTransport::with_client(opts, self.http.clone());
        Arc::new(inner)
    }
}

// ---------------------------------------------------------------------------
// Entrypoint
// ---------------------------------------------------------------------------

fn main() -> anyhow::Result<ExitCode> {
    // Publish the version so that `coauth-backend` can use it for telemetry,
    // the AppVersion depot entry, etc.
    coauth_backend::set_version(VERSION);

    let runtime = build_tokio_runtime()?;
    runtime.block_on(run_async())
}

/// Construct the Tokio runtime with all features enabled.
fn build_tokio_runtime() -> anyhow::Result<tokio::runtime::Runtime> {
    let mut builder = tokio::runtime::Builder::new_multi_thread();
    builder.enable_all();

    #[cfg(tokio_unstable)]
    builder
        .enable_metrics_poll_time_histogram()
        .metrics_poll_time_histogram_configuration(tokio::runtime::HistogramConfiguration::log(
            tokio::runtime::LogHistogram::default(),
        ));

    Ok(builder.build()?)
}

/// Top-level async wrapper that ensures telemetry is shut down regardless
/// of whether the command succeeded.
async fn run_async() -> anyhow::Result<ExitCode> {
    let outcome = execute_command().await;

    if let Err(err) = coauth_backend::telemetry::shutdown() {
        eprintln!("Failed to shutdown telemetry exporters: {err}");
    }

    outcome
}

/// The core async logic: env loading, logging, tracing, and command dispatch.
async fn execute_command() -> anyhow::Result<ExitCode> {
    // Attempt to load environment variables from .env files
    let dotenv_result: Result<Option<_>, _> = dotenvy::dotenv()
        .map(Some)
        .or_else(|e| if e.not_found() { Ok(None) } else { Err(e) });

    // Logging setup -- writes to stderr
    let stderr = std::io::stderr();
    let use_ansi = stderr.is_terminal();
    let (writer, _guard) = tracing_appender::non_blocking(stderr);
    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_writer(writer)
        .with_ansi(use_ansi);
    let env_filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new("info"))
        .context("could not setup logging filter")?;

    // Filter out noisy Jaeger propagator warnings about empty header values
    let jaeger_suppression = filter_fn(|meta| meta.name() != "JaegerPropagator.InvalidHeader");

    // Install the default rustls crypto provider
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("could not install the AWS LC crypto provider"))?;

    // Parse CLI arguments and load configuration
    let cli_opts = self::commands::Options::parse();
    let figment = cli_opts.figment();

    let mut tel_cfg = TelemetryConfig::extract_or_default(&figment)
        .map_err(anyhow::Error::from_boxed)
        .context("Failed to load telemetry config")?;
    if cli_opts.runs_server()
        && std::env::var(self::commands::METRICS_BIND_ENV)
            .is_ok_and(|value| !value.trim().is_empty())
    {
        tel_cfg.metrics.exporter = MetricsExporterKind::Prometheus;
    }

    // Sentry initialisation
    let sentry_guard = sentry::init((
        tel_cfg.sentry.dsn.as_deref(),
        sentry::ClientOptions {
            transport: Some(Arc::new(SentryTransportAdapter::create())),
            environment: tel_cfg.sentry.environment.clone().map(Into::into),
            release: Some(VERSION.into()),
            sample_rate: tel_cfg.sentry.sample_rate.unwrap_or(1.0),
            traces_sample_rate: tel_cfg.sentry.traces_sample_rate.unwrap_or(0.0),
            ..Default::default()
        },
    ));

    let sentry_layer = sentry_guard.is_enabled().then(|| {
        sentry_tracing::layer().event_filter(|md| {
            // Record 5xx response events as breadcrumbs rather than standalone
            // Sentry events to keep the noise level manageable.
            if md.name() == "http.server.response" {
                EventFilter::Breadcrumb
            } else {
                sentry_tracing::default_event_filter(md)
            }
        })
    });

    // OpenTelemetry tracing and metrics
    coauth_backend::telemetry::setup(&tel_cfg).context("failed to setup OpenTelemetry")?;

    let otel_tracer = coauth_backend::telemetry::TRACER
        .get()
        .context("TRACER was not set")?;

    let otel_layer = tracing_opentelemetry::layer()
        .with_tracer(otel_tracer.clone())
        .with_tracked_inactivity(false)
        .with_filter(LevelFilter::INFO);

    // Assemble and install the subscriber
    Registry::default()
        .with(jaeger_suppression)
        .with(sentry_layer)
        .with(otel_layer)
        .with(env_filter)
        .with(fmt_layer)
        .try_init()
        .context("could not initialize logging")?;

    // Report .env loading status
    match dotenv_result {
        Ok(Some(path)) => tracing::info!(?path, "Loaded environment variables from .env file"),
        Ok(None) => {}
        Err(e) => tracing::warn!(?e, "Failed to load .env file"),
    }

    tracing::trace!(?cli_opts, "Running command");
    cli_opts.run(&figment).await
}
