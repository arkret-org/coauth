# 运行服务

coauth 由两个主要组件组成：

1. **HTTP 服务器** — 处理所有 Web 请求（登录页面、OAuth 端点、管理 API 等）
2. **后台 Worker** — 处理异步任务（发送邮件、用户同步等）

默认情况下，`coauth server` 命令会同时启动这两个组件。

## 基本启动

```bash
coauth server -c config.yaml
```

## 运行时依赖

服务启动时需要能够访问以下资源：

- **PostgreSQL 数据库** — 存储用户、会话和配置数据
- **模板文件** — 渲染登录和注册页面（预编译版本已内置）
- **前端静态文件** — CSS、JavaScript 等资源
- **翻译文件** — 多语言界面支持

如果使用预编译二进制文件或 Docker 镜像，模板和前端文件已经内置。

## 启动选项

| 选项 | 说明 |
|------|------|
| `--no-migrate` | 启动时不自动执行数据库迁移 |
| `--no-worker` | 不启动后台任务 Worker |
| `--no-sync` | 不同步配置文件中的 OAuth 客户端和上游提供商到数据库 |

## 分离部署

在生产环境中，你可能希望将 HTTP 服务器和 Worker 分开部署：

```bash
# 启动 HTTP 服务器（不启动 Worker）
coauth server --no-worker -c config.yaml

# 在另一个进程中启动 Worker
coauth worker -c config.yaml
```

## systemd 服务配置

```ini
[Unit]
Description=coauth 认证服务
After=network.target postgresql.service

[Service]
ExecStart=/usr/local/bin/coauth server -c /etc/coauth/config.yaml
Restart=on-failure
User=coauth
Environment=RUST_LOG=info

[Install]
WantedBy=multi-user.target
```

## Docker Compose 示例

```yaml
services:
  coauth:
    image: ghcr.io/contrix-dev/coauth:latest
    command: server -c /config.yaml
    volumes:
      - ./config.yaml:/config.yaml:ro
      - ./keys:/keys:ro
    ports:
      - "8080:8080"
    depends_on:
      postgres:
        condition: service_healthy
    restart: unless-stopped

  postgres:
    image: postgres:16
    environment:
      POSTGRES_USER: coauth
      POSTGRES_PASSWORD: your_password
      POSTGRES_DB: coauth
    volumes:
      - pgdata:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U coauth"]
      interval: 5s
      timeout: 5s
      retries: 5

volumes:
  pgdata:
```

镜像默认以 distroless 非 root 用户运行，UID/GID 为 `65532`。
因此，配置文件中引用的所有文件路径都必须对该用户可读，而不只是挂载进容器即可。
这尤其包括 `secrets.keys[*].key_file`、`secrets.keys[*].password_file`、
`secrets.keys_dir` 和 `secrets.encryption_file`。

例如，如果配置里引用 `/keys/coauth-signing-key.pem`，宿主机挂载进去的文件必须允许
容器内的 `65532` 用户读取。
如果文件权限类似 `0600 root:root`，启动时就会报
`Permission denied (os error 13)`。
可以改成容器内可读的权限，例如 `chmod 0444`，或者通过所有者/ACL 授权给 `65532`。

## 日志配置

通过 `RUST_LOG` 环境变量控制日志级别：

```bash
# 显示所有 info 级别日志
RUST_LOG=info coauth server -c config.yaml

# 仅显示 coauth 相关的 debug 日志
RUST_LOG=coauth=debug coauth server -c config.yaml
```
