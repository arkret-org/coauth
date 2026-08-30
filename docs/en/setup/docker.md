# Running with Docker / Docker Compose

`coauth` can be built as a local OCI image for Docker or Docker Compose. This
local readiness workflow does not push registry images or publish release tags.
Use the same variant names for local image tags:

- `:latest` / `:vX.Y.Z` — distroless `nonroot` image, suitable for production.
- `:latest-debug` / `:vX.Y.Z-debug` — distroless `debug-nonroot` image with
  a busybox shell, useful for poking at a deployment.

Local image archives and provenance can be signed with
[Sigstore Cosign](https://docs.sigstore.dev/cosign/overview/) without registry
pushes or transparency-log uploads.

## Minimal `docker-compose.yaml`

```yaml
services:
  postgres:
    image: postgres:17-alpine
    environment:
      POSTGRES_USER: coauth
      POSTGRES_PASSWORD: change-me
      POSTGRES_DB: coauth
    volumes:
      - coauth-pg:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U coauth -d coauth"]
      interval: 10s
      timeout: 5s
      retries: 6
    restart: unless-stopped

  coauth:
    image: ghcr.io/arkret/coauth:latest
    depends_on:
      postgres:
        condition: service_healthy
    command: ["server", "--config", "/etc/coauth/config.yaml"]
    volumes:
      - ./config.yaml:/etc/coauth/config.yaml:ro
      - coauth-state:/var/lib/coauth
    ports:
      - "7080:7080"   # public HTTP listener
      - "8091:8091"   # internal listener (health, metrics)
    # The container declares its own HEALTHCHECK that smoke-tests the
    # binary. For real liveness / readiness the orchestrator should
    # probe the /healthz and /readyz endpoints on the internal listener.
    restart: unless-stopped

volumes:
  coauth-pg:
  coauth-state:
```

A minimal `config.yaml` to pair with this stack:

```yaml
http:
  public_base_url: http://localhost:7080/
  listeners:
    - name: public
      resources: [discovery, human, oauth, rest_api, assets]
      binds:
        - address: "[::]:7080"
    - name: internal
      resources: [health, prometheus]
      binds:
        - host: localhost
          port: 8091

database:
  uri: postgresql://coauth:change-me@postgres/coauth

arkret:
  admin_audience: ak:did_core:web:localhost
  stations:
    - name: soland
      endpoint: https://soland.example.com/
      service_id: ak:did_core:webvh:<soland-scid>
      embedded_webvh_registration_bearer: ${SOLAND_WEBVH_REGISTRATION_BEARER}

secrets:
  encryption: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
  keys:
    - key_file: /var/lib/coauth/signing.pem

passwords:
  enabled: true
```

## Health probes

The internal listener exposes `/health`, `/healthz`, and `/readyz`.
`/health` and `/healthz` return 200 OK when the database connection pool
is reachable. `/readyz` also checks that the public JWKS can be
materialized from the configured signing keys.

For Kubernetes:

```yaml
livenessProbe:
  httpGet:
    path: /healthz
    port: 8091
  initialDelaySeconds: 15
  periodSeconds: 30
readinessProbe:
  httpGet:
    path: /readyz
    port: 8091
  initialDelaySeconds: 5
  periodSeconds: 10
```

For Docker Compose users that want to override the built-in HEALTHCHECK
with a real `/healthz` or `/readyz` probe, a sidecar container with `curl` is the
simplest path; the distroless `coauth` image intentionally does not
ship `curl` or `wget`.

To keep Prometheus metrics on a separate listener, set
`COAUTH_METRICS_BIND`, for example `COAUTH_METRICS_BIND=127.0.0.1:9091`.
This adds a metrics-only listener at `/metrics`; see
[Observability](../observability.md#prometheus-metrics).

## Verifying image signatures

```sh
cosign verify \
  --certificate-identity-regexp 'https://github\.com/arkret/coauth/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/arkret/coauth:latest
```

## See also

- [Installation](installation.md) — pre-built binaries and source builds.
- [Running the service](running.md) — systemd, configuration, doctor.
- [Reverse proxy](reverse-proxy.md) — `X-Forwarded-For` /
  `trusted_proxies` setup, PROXY protocol.
- [`misc/systemd/coauth.service`](../../../misc/systemd/coauth.service)
  — sample systemd unit for non-Docker deployments.
