use schemars::JsonSchema;
use serde::{Deserialize, Serialize, de::Error as _};
use serde_with::skip_serializing_none;
use url::Url;

use super::ConfigurationSection;

/// Trace-context propagation format for distributed tracing
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Propagator {
    /// W3C Trace Context specification
    TraceContext,
    /// W3C Baggage specification
    Baggage,
    /// Jaeger-native propagation headers
    Jaeger,
}

/// Default OTLP collector endpoint used when none is explicitly configured
#[allow(clippy::unnecessary_wraps)]
fn otlp_endpoint_fallback() -> Option<String> {
    Some("https://localhost:4318".to_owned())
}

// ---------------------------------------------------------------------------
// Tracing
// ---------------------------------------------------------------------------

/// Destination for distributed trace spans
#[skip_serializing_none]
#[derive(Clone, Copy, Debug, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "lowercase")]
pub enum TracingExporterKind {
    /// Disable trace export
    #[default]
    None,
    /// Write traces to stdout (debugging only)
    Stdout,
    /// Ship traces via OTLP/HTTP
    Otlp,
}

/// Settings for distributed trace collection
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
pub struct TracingConfig {
    /// Where to send trace data
    #[serde(default)]
    pub exporter: TracingExporterKind,

    /// OTLP/HTTP collector URL
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(url, default = "otlp_endpoint_fallback")]
    pub endpoint: Option<Url>,

    /// Propagation formats attached to outgoing / parsed from incoming requests
    #[serde(default)]
    pub propagators: Vec<Propagator>,

    /// Fraction of traces to keep (0.0 -- 1.0). Defaults to `1.0`.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(example = 0.5, range(min = 0.0, max = 1.0))]
    pub sample_rate: Option<f64>,
}

impl TracingConfig {
    fn is_default(&self) -> bool {
        matches!(self.exporter, TracingExporterKind::None)
            && self.endpoint.is_none()
            && self.propagators.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Metrics
// ---------------------------------------------------------------------------

/// Destination for runtime metrics
#[skip_serializing_none]
#[derive(Clone, Copy, Debug, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "lowercase")]
pub enum MetricsExporterKind {
    /// Disable metric export
    #[default]
    None,
    /// Dump metrics to stdout (debugging only)
    Stdout,
    /// Ship metrics via OTLP/HTTP
    Otlp,
    /// Expose a Prometheus scrape endpoint (requires a `prometheus` HTTP
    /// resource)
    Prometheus,
}

/// Settings for runtime metric collection
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
pub struct MetricsConfig {
    /// Where to send metric data
    #[serde(default)]
    pub exporter: MetricsExporterKind,

    /// OTLP/HTTP collector URL
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(url, default = "otlp_endpoint_fallback")]
    pub endpoint: Option<Url>,
}

impl MetricsConfig {
    fn is_default(&self) -> bool {
        matches!(self.exporter, MetricsExporterKind::None) && self.endpoint.is_none()
    }
}

// ---------------------------------------------------------------------------
// Sentry
// ---------------------------------------------------------------------------

/// Sentry error-tracking integration
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
pub struct SentryConfig {
    /// Sentry Data Source Name (DSN)
    #[schemars(url, example = &"https://public@host:port/1")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dsn: Option<String>,

    /// Sentry environment tag (defaults to `production`)
    #[schemars(example = &"production")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,

    /// Fraction of events forwarded to Sentry (0.0 -- 1.0). Default: `1.0`.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(example = 0.5, range(min = 0.0, max = 1.0))]
    pub sample_rate: Option<f32>,

    /// Fraction of tracing transactions sent to Sentry (0.0 -- 1.0). Default:
    /// `0.0`.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(example = 0.5, range(min = 0.0, max = 1.0))]
    pub traces_sample_rate: Option<f32>,
}

impl SentryConfig {
    fn is_default(&self) -> bool {
        self.dsn.is_none()
    }
}

// ---------------------------------------------------------------------------
// Top-level telemetry
// ---------------------------------------------------------------------------

/// Observability and monitoring knobs
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
pub struct TelemetryConfig {
    /// Distributed tracing settings
    #[serde(default, skip_serializing_if = "TracingConfig::is_default")]
    pub tracing: TracingConfig,

    /// Runtime metrics settings
    #[serde(default, skip_serializing_if = "MetricsConfig::is_default")]
    pub metrics: MetricsConfig,

    /// Sentry error-reporting settings
    #[serde(default, skip_serializing_if = "SentryConfig::is_default")]
    pub sentry: SentryConfig,
}

impl TelemetryConfig {
    /// `true` when every sub-section is still at its default values
    pub(crate) fn is_default(&self) -> bool {
        self.tracing.is_default() && self.metrics.is_default() && self.sentry.is_default()
    }
}

/// Validates sample-rate ranges across all sub-sections
fn check_sample_rate_bounds(
    value: Option<impl Into<f64> + Copy>,
    label: &str,
    path: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    if let Some(rate) = value {
        let r: f64 = rate.into();
        if !(0.0..=1.0).contains(&r) {
            return Err(figment::error::Error::custom(format!(
                "{label} sample rate must be between 0.0 and 1.0"
            ))
            .with_path(path)
            .into());
        }
    }
    Ok(())
}

impl ConfigurationSection for TelemetryConfig {
    const PATH: &'static str = "telemetry";

    fn validate(
        &self,
        _figment: &figment::Figment,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        check_sample_rate_bounds(self.sentry.sample_rate, "Sentry", "sentry.sample_rate")?;
        check_sample_rate_bounds(
            self.sentry.traces_sample_rate,
            "Sentry",
            "sentry.traces_sample_rate",
        )?;
        check_sample_rate_bounds(
            self.tracing.sample_rate.map(|v| v as f64),
            "Tracing",
            "tracing.sample_rate",
        )?;
        Ok(())
    }
}
