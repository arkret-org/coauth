# 使用 Docker / Docker Compose 运行

`coauth` 在 `ghcr.io/arkret/coauth` 发布 OCI 镜像，每个版本提供两种变体：

- `:latest` / `:vX.Y.Z` —— distroless `nonroot`，适合生产环境。
- `:latest-debug` / `:vX.Y.Z-debug` —— distroless `debug-nonroot`，自带 BusyBox shell，方便排查问题。

镜像同时提供 `linux/amd64` 与 `linux/arm64`，并使用
[Sigstore Cosign](https://docs.sigstore.dev/cosign/overview/) 进行签名。

## 最小 `docker-compose.yaml`

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
      - "7080:7080"   # 公网 HTTP listener
      - "8091:8091"   # 内部 listener (health, metrics)
    restart: unless-stopped

volumes:
  coauth-pg:
  coauth-state:
```

镜像内置的 `HEALTHCHECK` 仅做二进制冒烟检查；真正的存活/就绪探测应该指向
内部 listener 上的 `/health`。

## 健康探测

内部 listener 暴露 `/health` 与 `/healthz`，数据库连接池可达时返回 `200 OK`。

Kubernetes 示例：

```yaml
livenessProbe:
  httpGet:
    path: /healthz
    port: 8091
  initialDelaySeconds: 15
  periodSeconds: 30
readinessProbe:
  httpGet:
    path: /health
    port: 8091
  initialDelaySeconds: 5
  periodSeconds: 10
```

## 验证镜像签名

```sh
cosign verify \
  --certificate-identity-regexp 'https://github\.com/arkret/coauth/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/arkret/coauth:latest
```

## 相关文档

- [安装](installation.md) —— 预编译二进制与从源码构建。
- [运行服务](running.md) —— systemd、配置、doctor。
- [配置反向代理](reverse-proxy.md) —— `X-Forwarded-For` /
  `trusted_proxies` 与 PROXY protocol 配置。
- [`misc/systemd/coauth.service`](../../../misc/systemd/coauth.service) ——
  非容器部署的 systemd unit 示例。
