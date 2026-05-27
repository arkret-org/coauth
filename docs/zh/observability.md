# 可观测性

`coauth` 通过 `tracing` 输出结构化日志，导出 OpenTelemetry trace
与 metric，并可通过 HTTP 暴露 Prometheus metric。

## OpenTelemetry collector

使用 `telemetry.tracing.exporter: otlp` 与
`telemetry.metrics.exporter: otlp` 将数据发送到 OTLP/HTTP collector。

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

下面这个本地 collector 配置接收来自 `coauth` 的 OTLP/HTTP，
并将 trace 转发到 Jaeger。`debug` exporter 在确认 metric 是
否抵达 collector 时很有用。

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

启动 collector 与 `coauth` 之后，打开
`http://127.0.0.1:16686`，查找 `coauth-backend` 服务。

## Prometheus 指标

Prometheus 抓取需要启用 Prometheus exporter，并通过带有
`prometheus` 资源的 HTTP listener 暴露：

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

抓取地址 `http://localhost:8091/metrics`。

对于希望将 metric 放在独立 socket 的部署，可以设置
`COAUTH_METRICS_BIND`。此变量会追加一个仅暴露 `/metrics` 的
listener，并启用 `coauth server` 的 Prometheus exporter。

```sh
COAUTH_METRICS_BIND=127.0.0.1:9091 coauth server
curl --fail http://127.0.0.1:9091/metrics
```

可接受的取值包括：单独的 TCP 端口、`host:port` 形式（如
`localhost:9091`），或 socket 地址（如 `127.0.0.1:9091` 或
`[::1]:9091`）。仅写端口时默认绑定 `127.0.0.1`。

## 健康与就绪检查

`health` 资源暴露三个探针端点：

- `/health`：存活类检查；确认 Postgres 连接池可达。
- `/healthz`：`/health` 的别名。
- `/readyz`：就绪检查；确认 Postgres 可达，并且可以从配置的
  签名密钥生成公共 JWKS。

在编排器中使用 `/healthz` 作为 liveness，`/readyz` 作为 readiness。
