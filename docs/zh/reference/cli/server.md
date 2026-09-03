# `server`

启动 coauth 认证服务。这是生产部署的主要命令。

## 用法

```bash
coauth server [选项] -c <配置文件>
```

## 选项

| 选项 | 说明 |
|------|------|
| `--no-migrate` | 启动时不自动执行数据库迁移 |
| `--no-worker` | 不启动后台任务 Worker |
| `--no-sync` | 不将配置文件中的 OAuth 客户端和上游提供商同步到数据库 |

## 启动流程

服务启动时按以下顺序执行：

1. **数据库迁移** — 应用所有待执行的 Schema 迁移（除非使用 `--no-migrate`）
2. **配置同步** — 将 OAuth 客户端和上游提供商定义同步到数据库（除非使用 `--no-sync`）
3. **密钥加载** — 加载签名密钥
4. **模板编译** — 加载并编译页面模板
5. **Worker 启动** — 启动后台任务 Worker（除非使用 `--no-worker`）
6. **HTTP 监听** — 开始接受连接

HTTP 监听不等待 Station trust 验证完成。OIDC discovery、公开 JWKS 和健康检查
端点会立即可用；后台验证成功前，业务路由返回 `503`，`/readyz` 返回未就绪。

## 健康与就绪检查

服务通过 `/health` 和 `/healthz` 提供存活检查，通过 `/readyz` 提供就绪检查。
`/readyz` 会检查 PostgreSQL、公开 JWKS 所需签名密钥以及 Station trust 是否就绪。

## 优雅关闭

服务支持通过 `SIGTERM` 或 `SIGINT`（Ctrl+C）信号进行优雅关闭：

1. 收到第一个信号后，停止接受新连接，等待进行中的请求完成
2. 收到第二个信号后，强制终止所有连接

## 示例

```bash
# 基本启动
coauth server -c config.yaml

# 不自动迁移，不启动 Worker
coauth server --no-migrate --no-worker -c config.yaml
```
