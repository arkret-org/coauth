# Observability

`coauth` emits structured logs through `tracing`, exports OpenTelemetry
traces and metrics, and can expose Prometheus metrics over HTTP.

## OpenTelemetry collector

Use `telemetry.tracing.exporter: otlp` and `telemetry.metrics.exporter: otlp`
to send data to an OTLP/HTTP collector.

```yaml
telemetry:
  tracing:
    exporter: otlp
    endpoint: http://127.0.0.1:4318/v1/traces
    propagators: [tracecontext, baggage]
  metrics:
    exporter: otlp
    endpoint: http://127.0.0.1:4318/v1/metrics
```

The following local collector setup accepts OTLP/HTTP from `coauth` and
forwards traces to Jaeger. The `debug` exporter is useful when confirming
that metrics are reaching the collector.

```yaml
services:
  jaeger:
    image: jaegertracing/all-in-one:latest
    ports:
      - "16686:16686"

  otel-collector:
    image: otel/opentelemetry-collector-contrib:latest
    command: ["--config=/etc/otelcol/config.yaml"]
    volumes:
      - ./otel-collector.yaml:/etc/otelcol/config.yaml:ro
    ports:
      - "4318:4318"
    depends_on:
      - jaeger
```

```yaml
receivers:
  otlp:
    protocols:
      http:
        endpoint: 0.0.0.0:4318

exporters:
  otlp/jaeger:
    endpoint: jaeger:4317
    tls:
      insecure: true
  debug:
    verbosity: basic

service:
  pipelines:
    traces:
      receivers: [otlp]
      exporters: [otlp/jaeger, debug]
    metrics:
      receivers: [otlp]
      exporters: [debug]
```

After starting the collector and `coauth`, open `http://127.0.0.1:16686`
and look for the `coauth-backend` service.

## Prometheus metrics

Prometheus scraping requires the Prometheus exporter and an HTTP listener
with the `prometheus` resource.

```yaml
telemetry:
  metrics:
    exporter: prometheus

http:
  listeners:
    - name: internal
      resources: [health, prometheus]
      binds:
        - host: localhost
          port: 8091
```

Scrape `http://localhost:8091/metrics`.

For deployments that keep metrics on a separate socket, set
`COAUTH_METRICS_BIND`. This appends a dedicated listener that exposes only
`/metrics`, and it enables the Prometheus exporter for `coauth server`.

```sh
COAUTH_METRICS_BIND=127.0.0.1:9091 coauth server
curl --fail http://127.0.0.1:9091/metrics
```

Accepted values are a bare TCP port, a `host:port` pair such as
`localhost:9091`, or a socket address such as `127.0.0.1:9091` or
`[::1]:9091`. A bare port binds to `127.0.0.1`.

## Health and readiness

The `health` resource exposes three probe endpoints:

- `/health`: liveness-style check; verifies the Postgres pool is reachable.
- `/healthz`: alias of `/health`.
- `/readyz`: readiness check; verifies Postgres is reachable and the public
  JWKS can be materialized from the configured signing keys.

Use `/healthz` for liveness and `/readyz` for readiness in orchestrators.
