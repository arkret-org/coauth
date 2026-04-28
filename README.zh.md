# Pasion

面向 [Palpo](https://palpo.im/) 的身份、通知、运营与接入平台。

## 概述

Pasion 不仅仅是一个认证服务，而是围绕 Palpo Matrix 服务器构建的完整用户身份和运营平台。它以 [MSC3861](https://github.com/matrix-org/matrix-doc/pull/3861) 为基础，提供 OAuth 2.0 / OpenID Connect 认证，同时将工作流编排、多渠道通知、外部系统接入和运营管理整合为一体，为 Matrix 生态提供企业级的用户全生命周期管理能力。

### 核心特性

- **工作流引擎** — 注册、恢复、验证流程以状态机方式管理，支持重试、审计和可观察性
- **统一通知中心** — Email + SMS 发送，支持多渠道抽象（SMTP、Twilio、阿里云短信、腾讯云短信）
- **Connector 平台** — 可插拔的外部系统接入（Palpo Matrix homeserver、上游 OAuth2 提供商）
- **中国生态 SSO** — 原生支持 QQ、微信、企业微信、飞书、Lark、钉钉等中国平台的非标准 OAuth 流程
- **Cedar + OPA 策略引擎** — 双策略后端支持，基于 WebAssembly 的细粒度访问控制
- **Dioxus 前端** — 全 Rust 构建的 SPA 前端，无需 TypeScript/React
- **运营管理 API** — 用户运营、风险处置、审计日志，RESTful JSON 接口
- **多渠道验证** — 邮箱 + 手机短信验证码，覆盖国内外用户
- **安全机制** — Argon2id 密码哈希、加密 Cookie、限流、CAPTCHA 支持
- **可观测性** — OpenTelemetry 链路追踪和 Prometheus 指标导出

## 快速开始

### 1. 安装

**预编译二进制 (Linux)**

```bash
curl -sL https://github.com/contrix-dev/coauth/releases/latest/download/coauth-x86_64-linux.tar.gz | tar xz
mv coauth /usr/local/bin/
```

**Docker**

```bash
docker pull ghcr.io/contrix-dev/coauth:latest
```

**从源码编译**

```bash
git clone https://github.com/contrix-dev/coauth.git
cd coauth
cd front && npm ci && npm run build && cd ..
cargo build --release
```

### 2. 准备数据库

```sql
CREATE USER coauth WITH PASSWORD 'your_password';
CREATE DATABASE coauth WITH OWNER coauth;
```

### 3. 生成并编辑配置

```bash
coauth config generate > config.yaml
# 编辑 config.yaml，参见下方配置说明
```

### 4. 启动服务

```bash
coauth server -c config.yaml
```

一条命令完成数据库迁移、启动 HTTP 服务和后台任务 worker。

## 配置说明

Pasion 使用 YAML 配置文件，核心配置项：

```yaml
# 公网访问地址
http:
  public_base: https://auth.example.com/
  listeners:
    - name: web
      binds:
        - address: "[::]:8080"
      resources:
        - name: discovery     # OIDC 发现端点
        - name: human         # 登录 / 注册 UI
        - name: oauth         # OAuth 2.0 端点
        - name: health        # 健康检查
        - name: assets        # 前端静态资源

# 数据库连接
database:
  uri: postgresql://coauth:password@localhost/coauth

# Matrix 服务器集成（Connector）
matrix:
  homeserver: matrix.example.com
  secret: "与 homeserver 共享的密钥"
  endpoint: "https://matrix.example.com"

# 加密与签名密钥
secrets:
  encryption: "base64编码的32字节密钥"
  keys:
    - kid: "key-id-1"
      key: |
        -----BEGIN RSA PRIVATE KEY-----
        ...
        -----END RSA PRIVATE KEY-----

# 密码认证
passwords:
  enabled: true
  schemes:
    - version: 1
      algorithm: argon2id

# 上游 SSO 提供商（Connector）
upstream_oauth2:
  providers:
    - id: "01HFRQFT5QFBM3Y5BHNFHMP6M0"
      issuer: "https://accounts.google.com"
      client_id: "your-client-id"
      client_secret: "your-client-secret"
      token_endpoint_auth_method: client_secret_post
      scope: "openid email profile"

# 邮件通知（多渠道通知中心）
email:
  from: '"Pasion" <noreply@example.com>'
  provider:
    type: resend
    api_key: "re_xxxxxxxxx"
    # 支持: smtp, sendmail, resend, sendgrid, twilio, brevo, aws_ses, http_webhook

# 短信通知（多渠道通知中心，支持 Twilio / 阿里云 / 腾讯云）
sms:
  provider:
    type: aliyun_sms
    access_key_id: "your-access-key-id"
    access_key_secret: "your-access-key-secret"
    sign_name: "你的签名"
    template_code: "SMS_123456789"
```

完整配置参考请查阅[配置文档](docs/zh/reference/configuration.md)。

在 Google / GitHub / 其他 upstream 平台后台登记应用时，callback URL 一律由 `http.public_base` 推导：

```text
<http.public_base>/upstream/callback/<provider-id>
```

例如 `http.public_base` 是 `https://auth.example.com/coauth/`，provider ID 是 `01JABCDEF0123456789ABCDEFG`，那么 callback URL 就是 `https://auth.example.com/coauth/upstream/callback/01JABCDEF0123456789ABCDEFG`。

## 部署架构

Pasion 部署在 Matrix homeserver 旁边，由反向代理统一接入。平台内部采用分层架构：HTTP 请求经路由层分发，由工作流引擎编排业务流程，底层通过仓储层（PostgreSQL）、Connector（Matrix homeserver / 上游 OAuth2）和通知中心（Email / SMS）完成交互。

```
              ┌───────────────┐
 用户 ───────>│   反向代理     │ (TLS 终止)
              └───────┬───────┘
                      │
         ┌────────────┼────────────┐
         │            │            │
    ┌────▼────┐  ┌────▼─────┐  ┌──▼──────────┐
    │ Pasion  │  │  Palpo   │  │   静态资源   │
    │ (平台)  │  │ (Matrix) │  │             │
    │  :8080  │  │  :8008   │  │             │
    └────┬────┘  └──────────┘  └─────────────┘
         │
    ┌────▼──────┐
    │ PostgreSQL │
    └───────────┘
```

### Palpo 服务器侧配置

在 Palpo 中配置 OIDC 委托，将认证交给 Pasion 处理：

```yaml
experimental_features:
  msc3861:
    enabled: true
    issuer: https://auth.example.com/
    client_id: 0000000000000000000PALPO
    client_auth_method: client_secret_basic
    client_secret: "你的密钥"
    admin_token: "管理员令牌"
    account_management_url: "https://auth.example.com/account/"
```

## CLI 命令参考

| 命令 | 说明 |
|------|------|
| `coauth server -c config.yaml` | 启动 HTTP 服务（默认命令） |
| `coauth config generate` | 生成默认配置文件 |
| `coauth config check -c config.yaml` | 校验配置文件 |
| `coauth config sync -c config.yaml` | 将 OAuth 客户端/上游提供商同步到数据库 |
| `coauth database migrate -c config.yaml` | 手动执行数据库迁移 |
| `coauth manage register-user` | 创建用户 |
| `coauth manage set-password` | 设置/重置用户密码 |
| `coauth manage promote-user` | 提升用户为管理员 |
| `coauth worker -c config.yaml` | 单独运行后台任务 worker |
| `coauth doctor -c config.yaml` | 诊断部署健康状态 |

### 服务启动选项

```bash
coauth server -c config.yaml                # 完整启动（默认）
coauth server -c config.yaml --no-worker    # 仅 HTTP 服务，不启动后台 worker
coauth server -c config.yaml --no-migrate   # 跳过自动数据库迁移
coauth server -c config.yaml --no-sync      # 跳过配置同步到数据库
```

## 上游 SSO 提供商

Pasion 的 Connector 平台支持与外部身份提供商联合登录。任何标准 OIDC 提供商均可开箱即用，同时为以下中国平台提供了原生适配，处理它们的非标准 OAuth2 流程：

| 提供商 | `token_endpoint_auth_method` | 说明 |
|--------|------------------------------|------|
| Google、GitLab、Keycloak、Authentik 等 | `client_secret_post` / `client_secret_basic` | 标准 OIDC |
| GitHub | `client_secret_post` | OAuth 2.0，需要手工配置 authorization/token/userinfo 端点 |
| Apple | `sign_in_with_apple` | Apple 专用 JWT 客户端密钥 |
| QQ | `qq_connect` | 非标准 token + 独立 OpenID 接口 |
| 微信 | `wechat` | 使用 `appid`/`secret`，token 包含 `openid` |
| 企业微信 | `wecom` | 企业 access_token + 用户身份解析 |
| 飞书 | `feishu` | 两步获取：先 app_access_token，再用户 token |
| Lark | `lark` | 国际版飞书，相同流程不同端点 |
| 钉钉 | `dingtalk` | JSON 请求体 + 自定义 access token 头 |

详细的提供商配置示例请参阅 [SSO 配置指南](docs/zh/setup/sso.md)。

## 生产部署

生产环境建议分离 HTTP 服务和后台 worker，可独立水平扩展：

```bash
# HTTP 服务（可负载均衡）
coauth server --no-worker -c config.yaml

# 后台 worker（可多实例运行，处理工作流状态推进、通知发送等异步任务）
coauth worker -c config.yaml
```

服务暴露的关键端点：

| 端点 | 用途 |
|------|------|
| `/health` | 健康检查 |
| `/healthz` | 健康检查别名 |
| `/metrics` | Prometheus 指标 |
| `/.well-known/openid-configuration` | OIDC 发现 |
| `/oauth2/authorize` | OAuth 2.0 授权 |
| `/oauth2/token` | Token 端点 |
| `/api/admin/v1/*` | 运营管理 API |

## 文档

完整文档请访问 <https://palpo-im.github.io/coauth/>。

| 章节 | 说明 |
|------|------|
| [安装部署](docs/zh/setup/installation.md) | 安装和配置 Pasion |
| [基础配置](docs/zh/setup/general.md) | 基础配置指引 |
| [数据库](docs/zh/setup/database.md) | 数据库配置与迁移 |
| [Homeserver 集成](docs/zh/setup/homeserver.md) | Palpo / Matrix 集成 |
| [反向代理](docs/zh/setup/reverse-proxy.md) | nginx / Caddy 配置 |
| [SSO 配置](docs/zh/setup/sso.md) | 上游身份提供商配置 |
| [配置参考](docs/zh/reference/configuration.md) | 完整配置选项 |
| [CLI 参考](docs/zh/reference/cli/) | 命令行工具文档 |
| [管理 API](docs/zh/topics/admin-api.md) | 通过 API 管理用户和会话 |
| [架构设计](docs/zh/development/architecture.md) | 内部设计和 crate 结构 |
| [参与贡献](docs/zh/development/contributing.md) | 如何参与项目贡献 |

## 系统要求

- **PostgreSQL** 17 或更高版本
- **Palpo** homeserver 0.2.1 或更高版本（或任何兼容的 Matrix homeserver）
- 反向代理（nginx、Caddy 等）用于 TLS 终止

## 许可证

Pasion 以 GNU Affero General Public License v3.0 only（`AGPL-3.0-only`）发布，详见 [LICENSE](LICENSE)。

部分文件按要求保留了上游版权和声明头。
