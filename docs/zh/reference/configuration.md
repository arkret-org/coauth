# 配置文件参考

`coauth` 使用 YAML 配置文件。可以先生成一份完整样例：

```bash
coauth config generate > config.yaml
```

`docs/config.schema.json` 来自 `coauth_config::RootConfig` 自动生成。环境变量覆盖使用
`COAUTH_` 前缀。

## `http`

控制公开 URL、监听器以及暴露哪些路由组。

```yaml
http:
  public_base: https://auth.example.com/
  issuer: https://auth.example.com/
  listeners:
    - name: web
      binds:
        - address: "[::]:8080"
      resources:
        - name: discovery
        - name: human
        - name: oauth
        - name: restapi
        - name: assets
          path: ./dist
        - name: adminapi  # 管理 API
```

### `http.listeners`

常见资源名：

- `discovery`：`/.well-known/*`
- `human`：浏览器页面
- `oauth`：OAuth / OIDC 端点
- `restapi`：SPA/API 后端
- `assets`：前端静态资源
- `adminapi`：`/_coauth/admin/*`
- `health`、`prometheus`：运维端点

### 请求体限制与超时

| 键 | 默认值 | 说明 |
| --- | --- | --- |
| `http.max_body_bytes` | `1048576` (1 MiB) | 请求体最大字节数；与 Arkret `ak.server.query.describe.limits.max_body_bytes` 对齐。 |
| `http.request_timeout_seconds` | `30` | 每请求处理超时；填 `0` 表示关闭。 |
| `http.shutdown_grace_seconds` | `30` | 收到 SIGTERM/SIGINT 后给在途请求的完成时间。 |
| `http.trusted_proxies` | RFC1918 + 回环 | 允许设置 `X-Forwarded-For` 的 CIDR 段，详见 [反向代理](../setup/reverse-proxy.md)。 |

## `database`

PostgreSQL 连接配置。

```yaml
database:
  uri: postgresql://coauth:password@localhost/coauth
  min_connections: 0
  max_connections: 10
  connect_timeout: 30
```

`coauth` 不应直接连接到 transaction pooling 模式的 pgBouncer / pgCat，因为服务依赖
需要 session 语义的 PostgreSQL 特性。

## `arkret`

Arkret 部署元数据，叠加在通用 OIDC server 之上。

```yaml
arkret:
  deployment_profile: organization
  principal_method: did:webvh

  principal_servers:
    - name: soland
      audience: did:webvh:<scid>:soland.example.com:webvh:service
      endpoint: https://soland.example.com/
      did: did:webvh:<scid>:soland.example.com:webvh:service

  identity_registry:
    kind: public_did_resolver
    resolver: https://resolver.example.com/
    proof_required_for_pairwise: true

  service_id: did:webvh:<scid>:auth.example.com:webvh:service
  issuer_did: did:webvh:<scid>:auth.example.com:webvh:service
  admin_audience: https://auth.example.com/_arkret
  session_grant_ttl: 300
```

- `principal_servers`：通过 Arkret discovery 发布的受信任 Principal Server 描述
- `deployment_profile`：身份部署 profile。只有 `personal_node` 可接受
  `did:web` principal DID。
- `principal_method`：principal DID 方法。默认 `did:webvh`；`did:web`
  必须显式搭配 `deployment_profile: personal_node`。
- `identity_registry`：委托的 DID / identity resolver，通常是 public DID resolver 服务
- `service_id`：显式 service DID；未配置时从 `http.public_base` 推导
- `issuer_did`：session grant 中写入的 DID；默认继承 `service_id`
- `admin_audience`：Arkret admin 集成期望的 audience；默认回退到本地 `/_arkret`
- `session_grant_ttl`：REST auth bridge 登录/交换路径以及 refresh endpoint
  返回的 Arkret session-grant JWT 生命周期，单位秒；默认 `300`（5 分钟）。

## `templates`

可选的 HTML 模板、翻译文件、前端资源 manifest 覆盖。

```yaml
templates:
  path: ./templates
  assets_manifest: ./dist/manifest.json
  translations_path: ./translations
```

## `clients`

静态 OAuth / OIDC client 注册项，会在启动时同步到数据库。

```yaml
clients:
  - client_id: 01HFVBY12TMNTYTBV8W921M5FA
    client_auth_method: client_secret_post
    client_secret: super-secret
    redirect_uris:
      - https://app.example.com/callback
```

## `secrets`

加密和签名密钥。

```yaml
secrets:
  encryption: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
  keys:
    - key_file: ./keys/signing.pem
```

至少应配置一把签名密钥。`coauth` 会用这些密钥签发 ID token、signed userinfo、JWKS，以及
Arkret session grant。

## `passwords`

本地密码登录配置。

```yaml
passwords:
  enabled: true
  minimum_complexity: 3
  schemes:
    - version: 1
      algorithm: argon2id
```

## `account`

自助账户管理开关。

```yaml
account:
  email_change_allowed: true
  displayname_change_allowed: true
  password_registration_enabled: false
  password_registration_contact_required: true
  registration_email_delivery_bypass_allowed: false
  password_change_allowed: true
  password_recovery_enabled: false
  account_deactivation_allowed: true
  login_with_email_allowed: false
  admin_portal_url: https://admin.example.com/
  registration_token_required: false
  bootstrap_admin_token: null
```

`bootstrap_admin_token` 是首个管理员账号的可选引导密钥。配置后，如果当前还没有管理员，
注册完成页会要求输入该 token；匹配成功的新账号会被标记为管理员。不输入 token 的注册
仍会作为普通用户完成；一旦系统里已有任意管理员，该 token 就不再授予管理员权限。

环境变量示例：

```bash
COAUTH_ACCOUNT__BOOTSTRAP_ADMIN_TOKEN=bootstrap-secret
```

## `captcha`

为登录、恢复、注册等易受滥用的流程配置 CAPTCHA。

```yaml
captcha:
  service: recaptcha_v2
  site_key: "site-key"
  secret_key: "secret-key"
```

## `policy`

授权策略引擎配置。

```yaml
policy:
  engine: cedar
  cedar_policy_file: ./policies/policies.cedar
```

当前项目原生支持 Cedar，也可以在编译相应 feature 后把决策委托给远端策略服务。

## `rate_limiting`

登录、恢复、注册等流程的限流配置。

```yaml
rate_limiting:
  login:
    per_ip:
      burst: 3
      per_second: 0.05
    per_account:
      burst: 1800
      per_second: 0.5
```

## `telemetry`

Tracing、metrics 和 Sentry 错误上报。

```yaml
telemetry:
  tracing:
    exporter: otlp
    endpoint: https://otel.example.com:4318
  metrics:
    exporter: prometheus
  sentry:
    dsn: https://public@host/1
```

## `email`

邮件发送配置。

```yaml
email:
  from: '"coauth" <noreply@example.com>'
  provider:
    type: resend
    api_key: re_xxxxxxxxx
```

支持的 provider family 包括 `blackhole`、`smtp`、`sendmail`、`resend`、
`sendgrid`、`twilio`、`brevo`、`aws_ses` 和 `http_webhook`。

## `sms`

短信发送配置。

```yaml
sms:
  provider:
    type: twilio
    account_sid: ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
    auth_token: your-auth-token
    from_number: "+12065550123"
```

## `upstream_oauth`

用于联邦登录的受信任 upstream OAuth / OIDC provider。

```yaml
upstream_oauth:
  providers:
    - id: 01HFVBY12TMNTYTBV8W921M5FA
      issuer: https://accounts.google.com
      client_id: your-client-id
      client_secret: your-client-secret
      token_endpoint_auth_method: client_secret_post
      scope: "openid email profile"
```

这个配置段会和 `clients` 一样，在启动时同步到数据库。

## `branding`

服务名、Logo、页脚链接、隐私政策、服务条款等品牌化配置。

```yaml
branding:
  service_name: Example Auth
  logo_uri: https://assets.example.com/logo.svg
  policy_uri: https://example.com/privacy
  tos_uri: https://example.com/terms
```

## `experimental`

还可能继续调整形态的实验性开关和时长参数。

```yaml
experimental:
  access_token_ttl: 300
```

## `storage`

文件或对象存储后端配置，用于上传资源和后续二进制工件。

```yaml
storage:
  backend: fs
```
