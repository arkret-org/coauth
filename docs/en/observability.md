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

`propagators` accepts `tracecontext` and `baggage`. Jaeger-native propagation
(`uber-trace-id`) is not supported: the format is deprecated by the
OpenTelemetry specification, and Jaeger has spoken W3C Trace Context since
1.35. Send traces to Jaeger over OTLP -- as the collector setup below does --
and keep `tracecontext` in this list.

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
- `/readyz`: readiness check; verifies Postgres is reachable, the public JWKS
  can be materialized from the KeyStore-backed signing keys, and every configured
  Station has completed online trust verification.

Use `/healthz` for liveness and `/readyz` for readiness in orchestrators.

### Example responses

`/healthz` (success):

```http
HTTP/1.1 200 OK
content-type: application/json

{
  "status": "ok",
  "checks": { "postgres": "ok" }
}
```

`/healthz` (failure — Postgres unreachable):

```http
HTTP/1.1 503 Service Unavailable
content-type: application/json

{
  "status": "fail",
  "checks": { "postgres": "fail: connection refused (after 3 retries)" }
}
```

`/readyz` (success — pool warm + JWKS materialized):

```http
HTTP/1.1 200 OK
content-type: application/json

{
  "status": "ready",
  "checks": {
    "postgres": "ok",
    "signing_keys": "ok (3 active keys, jwks materialized)"
  }
}
```

`/readyz` (failure — signing keys not yet materialized):

```http
HTTP/1.1 503 Service Unavailable
content-type: application/json

{
  "status": "not_ready",
  "checks": {
    "postgres": "ok",
    "signing_keys": "fail: no active key in keyring"
  }
}
```

`/metrics` (Prometheus text exposition; truncated):

```text
# HELP coauth_session_grant_total Total session grants issued by reason
# TYPE coauth_session_grant_total counter
coauth_session_grant_total{reason="ok"} 12345

# HELP coauth_revocation_mirror_age_seconds Age of mirrored revocation state
# TYPE coauth_revocation_mirror_age_seconds gauge
coauth_revocation_mirror_age_seconds 7

# HELP process_resident_memory_bytes Resident memory size in bytes
# TYPE process_resident_memory_bytes gauge
process_resident_memory_bytes 1.31e+08
```

### Prometheus scrape configuration

A minimal Prometheus scrape job for a single coauth instance running with
the metrics listener on `127.0.0.1:9091`:

```yaml
scrape_configs:
  - job_name: coauth
    metrics_path: /metrics
    scheme: http
    scrape_interval: 15s
    scrape_timeout: 5s
    static_configs:
      - targets:
          - "127.0.0.1:9091"
        labels:
          service: coauth
          deployment: prod
```

For Kubernetes (Prometheus Operator `ServiceMonitor`):

```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: coauth
  labels:
    release: prometheus
spec:
  selector:
    matchLabels:
      app.kubernetes.io/name: coauth
  endpoints:
    - port: metrics       # Service port named "metrics" pointing at 9091
      path: /metrics
      interval: 15s
      scrapeTimeout: 5s
```

Liveness / readiness probe snippets (Kubernetes):

```yaml
livenessProbe:
  httpGet:
    path: /healthz
    port: http
  initialDelaySeconds: 10
  periodSeconds: 15
  timeoutSeconds: 3
  failureThreshold: 3
readinessProbe:
  httpGet:
    path: /readyz
    port: http
  initialDelaySeconds: 5
  periodSeconds: 5
  timeoutSeconds: 2
  failureThreshold: 2
```
