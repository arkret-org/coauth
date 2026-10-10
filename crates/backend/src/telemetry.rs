use std::sync::{LazyLock, OnceLock};

use anyhow::Context as _;
use coauth_config::{
    MetricsConfig, MetricsExporterKind, Propagator, TelemetryConfig, TracingConfig,
    TracingExporterKind,
};
use hyper::header::CONTENT_TYPE;
use opentelemetry::metrics::Meter;
use opentelemetry::propagation::{TextMapCompositePropagator, TextMapPropagator};
use opentelemetry::trace::TracerProvider as _;
use opentelemetry::{InstrumentationScope, KeyValue};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_prometheus::PrometheusExporter;
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::metrics::periodic_reader_with_async_runtime::PeriodicReader;
use opentelemetry_sdk::metrics::{ManualReader, SdkMeterProvider};
use opentelemetry_sdk::propagation::{BaggagePropagator, TraceContextPropagator};
use opentelemetry_sdk::trace::span_processor_with_async_runtime::BatchSpanProcessor;
use opentelemetry_sdk::trace::{IdGenerator, Sampler, SdkTracerProvider, Tracer};
use opentelemetry_semantic_conventions as semcov;
use prometheus::{Encoder as _, Registry, TextEncoder};

static SCOPE: LazyLock<InstrumentationScope> = LazyLock::new(|| {
    InstrumentationScope::builder(env!("CARGO_PKG_NAME"))
        .with_version(env!("CARGO_PKG_VERSION"))
        .with_schema_url(semcov::SCHEMA_URL)
        .build()
});

pub static METER: LazyLock<Meter> =
    LazyLock::new(|| opentelemetry::global::meter_with_scope(SCOPE.clone()));

pub static TRACER: OnceLock<Tracer> = OnceLock::new();
static METER_PROVIDER: OnceLock<SdkMeterProvider> = OnceLock::new();
static TRACER_PROVIDER: OnceLock<SdkTracerProvider> = OnceLock::new();
static PROMETHEUS_REGISTRY: OnceLock<Registry> = OnceLock::new();

pub fn setup(config: &TelemetryConfig) -> anyhow::Result<()> {
    let propagator = propagator(&config.tracing.propagators);

    opentelemetry::global::set_text_map_propagator(propagator);

    init_tracer(&config.tracing).context("Failed to configure traces exporter")?;
    init_meter(&config.metrics).context("Failed to configure metrics exporter")?;

    opentelemetry_instrumentation_process::init()
        .context("Failed to configure process instrumentation")?;
    opentelemetry_instrumentation_tokio::observe_current_runtime();

    Ok(())
}

pub fn shutdown() -> opentelemetry_sdk::error::OTelSdkResult {
    if let Some(tracer_provider) = TRACER_PROVIDER.get() {
        tracer_provider.shutdown()?;
    }

    if let Some(meter_provider) = METER_PROVIDER.get() {
        meter_provider.shutdown()?;
    }

    Ok(())
}

fn match_propagator(propagator: Propagator) -> Box<dyn TextMapPropagator + Send + Sync> {
    use Propagator as P;
    match propagator {
        P::TraceContext => Box::new(TraceContextPropagator::new()),
        P::Baggage => Box::new(BaggagePropagator::new()),
    }
}

fn propagator(propagators: &[Propagator]) -> TextMapCompositePropagator {
    let propagators = propagators.iter().copied().map(match_propagator).collect();

    TextMapCompositePropagator::new(propagators)
}

/// An [`IdGenerator`] which always returns an invalid trace ID and span ID
///
/// This is used when no exporter is being used, so that we don't log the trace
/// ID when we're not tracing.
#[derive(Debug, Clone, Copy)]
struct InvalidIdGenerator;
impl IdGenerator for InvalidIdGenerator {
    fn new_trace_id(&self) -> opentelemetry::TraceId {
        opentelemetry::TraceId::INVALID
    }
    fn new_span_id(&self) -> opentelemetry::SpanId {
        opentelemetry::SpanId::INVALID
    }
}

fn init_tracer(config: &TracingConfig) -> anyhow::Result<()> {
    let sample_rate = config.sample_rate.unwrap_or(1.0);

    // We sample traces based on the parent if we have one, and if not, we
    // sample a ratio based on the configured sample rate
    let sampler = Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(sample_rate)));

    let tracer_provider_builder = SdkTracerProvider::builder()
        .with_resource(resource())
        .with_sampler(sampler);

    let tracer_provider = match config.exporter {
        TracingExporterKind::None => tracer_provider_builder
            .with_id_generator(InvalidIdGenerator)
            .with_sampler(Sampler::AlwaysOff)
            .build(),

        TracingExporterKind::Stdout => {
            let exporter = opentelemetry_stdout::SpanExporter::default();
            tracer_provider_builder
                .with_simple_exporter(exporter)
                .build()
        }

        TracingExporterKind::Otlp => {
            let mut exporter = opentelemetry_otlp::SpanExporter::builder().with_http();
            if let Some(endpoint) = &config.endpoint {
                exporter = exporter.with_endpoint(endpoint.as_str());
            }
            let exporter = exporter
                .build()
                .context("Failed to configure OTLP trace exporter")?;

            let batch_processor =
                BatchSpanProcessor::builder(exporter, opentelemetry_sdk::runtime::Tokio).build();

            tracer_provider_builder
                .with_span_processor(batch_processor)
                .build()
        }
    };

    TRACER_PROVIDER
        .set(tracer_provider.clone())
        .map_err(|_| anyhow::anyhow!("TRACER_PROVIDER was set twice"))?;

    let tracer = tracer_provider.tracer_with_scope(SCOPE.clone());
    TRACER
        .set(tracer)
        .map_err(|_| anyhow::anyhow!("TRACER was set twice"))?;

    opentelemetry::global::set_tracer_provider(tracer_provider);

    Ok(())
}

fn otlp_metric_reader(
    endpoint: Option<&url::Url>,
) -> anyhow::Result<PeriodicReader<opentelemetry_otlp::MetricExporter>> {
    let mut exporter = opentelemetry_otlp::MetricExporter::builder().with_http();
    if let Some(endpoint) = endpoint {
        exporter = exporter.with_endpoint(endpoint.to_string());
    }
    let exporter = exporter
        .build()
        .context("Failed to configure OTLP metric exporter")?;

    let reader = PeriodicReader::builder(exporter, opentelemetry_sdk::runtime::Tokio).build();
    Ok(reader)
}

fn stdout_metric_reader() -> PeriodicReader<opentelemetry_stdout::MetricExporter> {
    let exporter = opentelemetry_stdout::MetricExporter::builder().build();
    PeriodicReader::builder(exporter, opentelemetry_sdk::runtime::Tokio).build()
}

/// Salvo handler for serving Prometheus metrics.
#[salvo::handler]
pub async fn prometheus_handler(res: &mut salvo::Response) {
    if let Some(registry) = PROMETHEUS_REGISTRY.get() {
        let encoder = TextEncoder::new();
        let mut buffer = Vec::with_capacity(1024);

        if let Err(err) = encoder.encode(&registry.gather(), &mut buffer) {
            tracing::error!(
                error = &err as &dyn std::error::Error,
                "Failed to export Prometheus metrics"
            );

            res.status_code(salvo::http::StatusCode::INTERNAL_SERVER_ERROR);
            res.headers_mut()
                .insert(CONTENT_TYPE, "text/plain".parse().unwrap());
            res.render(salvo::writing::Text::Plain(
                "Failed to export Prometheus metrics, see logs for details",
            ));
        } else {
            res.status_code(salvo::http::StatusCode::OK);
            res.headers_mut()
                .insert(CONTENT_TYPE, encoder.format_type().parse().unwrap());
            res.render(salvo::writing::Text::Plain(
                String::from_utf8_lossy(&buffer).into_owned(),
            ));
        }
    } else {
        res.status_code(salvo::http::StatusCode::INTERNAL_SERVER_ERROR);
        res.headers_mut()
            .insert(CONTENT_TYPE, "text/plain".parse().unwrap());
        res.render(salvo::writing::Text::Plain(
            "Prometheus exporter was not enabled in config",
        ));
    }
}

fn prometheus_metric_reader() -> anyhow::Result<PrometheusExporter> {
    let registry = Registry::new();
    let exporter = build_prometheus_exporter(registry.clone())?;

    PROMETHEUS_REGISTRY
        .set(registry)
        .map_err(|_| anyhow::anyhow!("PROMETHEUS_REGISTRY was set twice"))?;

    Ok(exporter)
}

fn build_prometheus_exporter(registry: Registry) -> anyhow::Result<PrometheusExporter> {
    opentelemetry_prometheus::exporter()
        .without_scope_info()
        .with_registry(registry)
        .build()
        .context("Failed to configure Prometheus metric exporter")
}

fn init_meter(config: &MetricsConfig) -> anyhow::Result<()> {
    let meter_provider_builder = SdkMeterProvider::builder();
    let meter_provider_builder = match config.exporter {
        MetricsExporterKind::None => meter_provider_builder.with_reader(ManualReader::default()),
        MetricsExporterKind::Stdout => meter_provider_builder.with_reader(stdout_metric_reader()),
        MetricsExporterKind::Otlp => {
            meter_provider_builder.with_reader(otlp_metric_reader(config.endpoint.as_ref())?)
        }
        MetricsExporterKind::Prometheus => {
            meter_provider_builder.with_reader(prometheus_metric_reader()?)
        }
    };

    let meter_provider = meter_provider_builder.with_resource(resource()).build();

    METER_PROVIDER
        .set(meter_provider.clone())
        .map_err(|_| anyhow::anyhow!("METER_PROVIDER was set twice"))?;
    opentelemetry::global::set_meter_provider(meter_provider.clone());

    Ok(())
}

fn resource() -> Resource {
    Resource::builder()
        .with_service_name(env!("CARGO_PKG_NAME"))
        .with_detectors(&[
            Box::new(opentelemetry_resource_detectors::HostResourceDetector::default()),
            Box::new(opentelemetry_resource_detectors::OsResourceDetector),
            Box::new(opentelemetry_resource_detectors::ProcessResourceDetector),
        ])
        .with_attributes([
            KeyValue::new(semcov::resource::SERVICE_VERSION, crate::version()),
            KeyValue::new(semcov::resource::PROCESS_RUNTIME_NAME, "rust"),
            KeyValue::new(
                semcov::resource::PROCESS_RUNTIME_VERSION,
                env!("VERGEN_RUSTC_SEMVER"),
            ),
        ])
        .build()
}

#[cfg(test)]
mod tests {
    use opentelemetry::metrics::MeterProvider as _;

    use super::*;

    #[test]
    fn prometheus_scrape_preserves_counters_histograms_and_labels() {
        let registry = Registry::new();
        let exporter = build_prometheus_exporter(registry.clone()).unwrap();
        let provider = SdkMeterProvider::builder().with_reader(exporter).build();
        let meter = provider.meter("coauth-ci");
        let counter = meter.u64_counter("coauth_ci_requests").build();
        let histogram = meter
            .f64_histogram("coauth_ci_request_duration")
            .with_unit("s")
            .build();
        let attributes = [KeyValue::new("method", "GET")];
        counter.add(2, &attributes);
        histogram.record(0.5, &attributes);

        let encoder = TextEncoder::new();
        let mut buffer = Vec::new();
        encoder.encode(&registry.gather(), &mut buffer).unwrap();
        let output = String::from_utf8(buffer).unwrap();
        assert!(output.contains("# TYPE coauth_ci_requests_total counter"));
        assert!(output.contains("coauth_ci_requests_total{method=\"GET\"} 2"));
        assert!(output.contains("# TYPE coauth_ci_request_duration_seconds histogram"));
        assert!(output.contains("coauth_ci_request_duration_seconds_count{method=\"GET\"} 1"));
        assert!(output.contains("coauth_ci_request_duration_seconds_sum{method=\"GET\"} 0.5"));
        assert!(!output.contains("otel_scope"));
        assert_eq!(encoder.format_type(), "text/plain; version=0.0.4");
        provider.shutdown().unwrap();
    }
}
