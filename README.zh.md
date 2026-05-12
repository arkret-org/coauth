# coauth

`coauth` 是 Contrix 的 Auth / Account Server，负责提供 OIDC/OAuth2 登录、
账号生命周期管理、短时 session grant、策略钩子、通知能力，以及稳定的管理 API。

`coauth` 不是 DID Registry。它负责证明“谁登录了哪个本地账号、设备和会话”，再把这
些状态发布给 Principal Server 和管理工具。DID document、key-log、registry
receipt 等能力属于委托的 public DID resolver / DID 服务。

## 集成模型

- `yougen` 作为 Contrix 的 public/native client，消费 OIDC token。
- Principal Server（例如 `soland`）从 `coauth` 获取 session grant 和账号元数据。
- `sodmin` 通过 `urn:coauth:admin` 或 `urn:contrix:admin:*` 访问管理 API。
- 委托的 public DID resolver / DID 服务继续作为 identity registry / resolver。
- Matrix / Palpo 集成保留为 legacy compatibility adapter，不再是主产品路径。

## 当前状态

仓库仍在从早期的 Pasion / Matrix 语境迁移。当前已经以 Contrix 为主路径暴露：

- `/.well-known/openid-configuration`
- `/.well-known/did.json`
- `/api/v1/server/describe`
- `/api/v1/identity/describe`
- `/api/v1/directory/resolve-handle`

非主路径里仍然保留了一些 legacy naming 和 compatibility code。剩余迁移项见
[`_todos.md`](_todos.md)。

## 主要能力

- OpenID Connect Provider，支持 authorization code、refresh token、
  client credentials 和 device code grant
- Contrix discovery、service DID document、handle 解析、短时 session grant
- 本地账号生命周期、密码登录、上游 OAuth2 联邦、恢复流程
- 面向 session、token、user、client、template、connector、policy data 的管理 API
- Email / SMS 通知、限流、CAPTCHA 钩子、telemetry、策略执行
- 仍可为需要 delegated-auth bridge 的部署提供 Matrix / Palpo legacy adapter

## 快速开始

### 1. 生成配置

```bash
coauth config generate > config.yaml
```

### 2. 填写部署相关配置

```yaml
http:
  public_base: https://auth.example.com/

database:
  uri: postgresql://coauth:password@localhost/coauth

contrix:
  principal_servers:
    - name: soland
      audience: https://soland.example.com/api
      endpoint: https://soland.example.com/
      did: did:web:soland.example.com
  identity_registry:
    kind: public_did_resolver
    resolver: https://resolver.example.com/
    proof_required_for_pairwise: true
  service_did: did:web:auth.example.com
  issuer_did: did:web:auth.example.com
  admin_audience: https://auth.example.com/api/v1

secrets:
  encryption: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
  keys:
    - key_file: ./keys/signing.pem

passwords:
  enabled: true

matrix:
  homeserver: matrix.example.com
  secret: legacy-shared-secret
  endpoint: https://matrix.example.com/
```

当前代码里的 `matrix` 段还没有完全拆到独立 compatibility profile，所以它仍在
根配置模型中。除非你正在启用 Matrix / Palpo 兼容路径，否则应把它视为 legacy
integration config。

### 3. 启动服务

```bash
coauth server -c config.yaml
```

该命令会执行迁移、同步配置型状态、启动 HTTP 服务，并在未关闭的情况下拉起后台 worker。

## 从源码构建

`coauth` 是 Rust workspace，前端使用 Dioxus。

```bash
git clone https://github.com/contrix-dev/coauth.git
cd coauth

# 仅构建后端二进制
cargo build --release -p coauth

# 构建完整生产产物（需要 `just` 和 `dx`）
just build-all
```

## 关键端点

| 端点 | 用途 |
|------|------|
| `/.well-known/openid-configuration` | OIDC discovery |
| `/.well-known/did.json` | 服务 DID document |
| `/api/v1/server/describe` | Contrix 服务元数据 |
| `/api/v1/identity/describe` | identity-registry contract |
| `/api/v1/directory/resolve-handle` | handle -> DID 解析 |
| `/api/admin/v1/*` | 提供给 `sodmin` 和内部自动化的管理 API |

## 文档

- 英文配置参考: [docs/en/reference/configuration.md](docs/en/reference/configuration.md)
- 英文 scope 参考: [docs/en/reference/scopes.md](docs/en/reference/scopes.md)
- 中文配置参考: [docs/zh/reference/configuration.md](docs/zh/reference/configuration.md)
- 中文 scope 参考: [docs/zh/reference/scopes.md](docs/zh/reference/scopes.md)

## 许可证

`coauth` 以 `AGPL-3.0-only` 发布，详见 [LICENSE](LICENSE)。
