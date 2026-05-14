# 配置上游 SSO 提供商

coauth 支持把外部身份提供商接入为 upstream，用于登录、注册和账户关联。

常见场景分两类：

- 标准 OIDC 提供商：Google、GitLab、Keycloak、Authentik、Azure AD 等
- 非标准 OAuth 提供商：GitHub，以及 QQ / 微信 / 飞书 / 钉钉等需要自定义端点或特殊 token 交换逻辑的平台

如果你只关心「GitHub / Google 怎么配」和「callback URL 到底是什么」，先看下面两节。

## 先确定 callback URL

上游提供商后台里要登记的回调地址，不是手写一个固定模板，而是由 **`http.public_base` + provider `id`** 计算出来的。

格式是：

```text
<http.public_base>/upstream/callback/<provider-id>
```

其中：

- `http.public_base` 必须是外部用户和第三方提供商都能访问到的公网地址
- `<provider-id>` 就是 `upstream_oauth.providers[].id`，必须和配置文件里的值完全一致
- 如果 `http.public_base` 带有路径前缀，这个前缀也必须保留在 callback URL 里

例如：

- `http.public_base: https://auth.example.com/`
  callback URL: `https://auth.example.com/upstream/callback/01JABCDEF0123456789ABCDEFG`
- `http.public_base: https://example.com/coauth/`
  callback URL: `https://example.com/coauth/upstream/callback/01JABCDEF0123456789ABCDEFG`

如果 provider 支持 OpenID Connect Back-Channel Logout，对应地址是：

```text
<http.public_base>/upstream/backchannel-logout/<provider-id>
```

注意这几个常见误区：

- 在 Google / GitHub 后台登记的是 `/upstream/callback/<provider-id>`，不是 `/upstream/authorize/<provider-id>`
- callback URL 必须和 provider 后台登记的值完全一致，域名、协议、端口、路径前缀都不能错
- 不要把内网地址、容器内部地址或 `localhost` 当作 `http.public_base`，除非第三方平台真的能访问它

## 通用配置步骤

1. 先确定 `http.public_base`
2. 为每个 upstream 生成一个唯一 `id`，格式必须是 ULID
3. 用这个 `id` 计算 callback URL，并登记到 Google / GitHub / 其他 provider 后台
4. 把 provider 的 `client_id`、`client_secret` 和必要端点写进 `upstream_oauth.providers`
5. 启动服务或执行 `coauth config sync -c config.yaml` 把配置同步到数据库

一个最小的标准 OIDC 配置通常长这样：

```yaml
upstream_oauth:
  providers:
    - id: 01JABCDEF0123456789ABCDEFG
      human_name: Example OIDC
      client_id: "your-client-id"
      client_secret: "your-client-secret"
      issuer: "https://id.example.com"
      token_endpoint_auth_method: client_secret_post
      scope: "openid profile email"
      claims_imports:
        username:
          action: ignore
        displayname:
          action: suggest
          template: "{{ user.name }}"
        email:
          action: suggest
          template: "{{ user.email }}"
```

几个关键点：

- 只要 `discovery_mode` 没设成 `disabled`，`issuer` 就是必填项
- `issuer` 必须和 provider 的 `/.well-known/openid-configuration` 返回的 `issuer` 完全一致
- 多数标准 OIDC provider 用 `scope: "openid profile email"` 就够了
- 如果你不想让 upstream 自动决定 本地用户名，`username.action` 用 `ignore` 最稳

## Google

Google 属于标准 OIDC 提供商，直接走 discovery 即可。

在 Google Cloud Console 中：

1. 打开 `APIs & Services` -> `Credentials`
2. 创建 `OAuth client ID`
3. Application type 选择 `Web application`
4. 在 `Authorized redirect URIs` 中填写：
   `https://<你的对外域名>/upstream/callback/<provider-id>`
5. 记录生成的 `Client ID` 和 `Client Secret`

coauth 配置示例：

```yaml
upstream_oauth:
  providers:
    - id: 01JABCDEF0123456789ABCDEG1
      human_name: Google
      brand_name: google
      issuer: "https://accounts.google.com"
      client_id: "your-google-client-id.apps.googleusercontent.com"
      client_secret: "your-google-client-secret"
      token_endpoint_auth_method: client_secret_post
      scope: "openid profile email"
      claims_imports:
        username:
          action: ignore
        displayname:
          action: suggest
          template: "{{ user.name }}"
        email:
          action: suggest
          template: "{{ user.email }}"
        account_name:
          template: "{{ user.email }}"
```

说明：

- `issuer` 推荐写成 `https://accounts.google.com`，不要额外加尾部 `/`
- callback URL 里的 `<provider-id>` 必须是这条配置里的 `id`
- 如果你的 coauth 部署在子路径下，例如 `https://example.com/coauth/`，Google 后台里也必须登记带子路径的完整 callback URL

## GitHub

GitHub 不是标准 OIDC provider。coauth 对 GitHub 使用的是 OAuth + 手工指定端点 + `userinfo` 拉取资料的模式。

在 GitHub Developer Settings 中：

1. 打开 [OAuth Apps](https://github.com/settings/developers)
2. 创建新的 OAuth App
3. `Homepage URL` 填你的站点地址
4. `Authorization callback URL` 填：
   `https://<你的对外域名>/upstream/callback/<provider-id>`
5. 保存后拿到 `Client ID`
6. 生成并保存 `Client Secret`

coauth 配置示例：

```yaml
upstream_oauth:
  providers:
    - id: 01JABCDEF0123456789ABCDEG2
      human_name: GitHub
      brand_name: github
      discovery_mode: disabled
      fetch_userinfo: true
      token_endpoint_auth_method: client_secret_post
      client_id: "your-github-client-id"
      client_secret: "your-github-client-secret"
      authorization_endpoint: "https://github.com/login/oauth/authorize"
      token_endpoint: "https://github.com/login/oauth/access_token"
      userinfo_endpoint: "https://api.github.com/user"
      scope: "read:user user:email"
      claims_imports:
        subject:
          template: "{{ userinfo_claims.id }}"
        displayname:
          action: suggest
          template: "{{ userinfo_claims.name or userinfo_claims.login }}"
        username:
          action: ignore
        email:
          action: suggest
          template: "{{ userinfo_claims.email }}"
        account_name:
          template: "@{{ userinfo_claims.login }}"
```

说明：

- GitHub 这里不能照抄标准 OIDC 配置，必须 `discovery_mode: disabled`
- `subject` 也不能用默认值，必须手动映射到 `{{ userinfo_claims.id }}`
- GitHub 某些账户不会返回邮箱，即使授权成功，`userinfo_claims.email` 也可能为空
- 如果你不希望邮箱缺失影响注册体验，保持 `email.action: suggest` 或直接改成 `ignore`

## 其他标准 OIDC provider

GitLab、Keycloak、Authentik、Azure AD 等标准 OIDC 提供商，原则上都遵循同一套规则：

- callback URL 一律是 `<http.public_base>/upstream/callback/<provider-id>`
- `issuer` 必须精确匹配 provider 公布的 issuer
- 大多数情况下使用 `scope: "openid profile email"`
- 如果 provider 支持 backchannel logout，可额外登记 `<http.public_base>/upstream/backchannel-logout/<provider-id>`

这些 provider 的更完整英文示例可以参考英文文档：[docs/en/setup/sso.md](../../en/setup/sso.md)

## 用户属性映射

`claims_imports` 决定 upstream 返回的数据如何映射到本地账户：

| 字段 | 说明 |
|------|------|
| `subject` | 上游身份的唯一标识，用来建立账号关联 |
| `username` | 本地账户用户名 |
| `displayname` | 显示名 |
| `email` | 邮箱 |
| `avatar` | 头像 URL |
| `account_name` | 仅用于 UI 展示，帮助用户识别自己用的是哪个上游账号 |

常见 `action`：

| `action` | 行为 |
|----------|------|
| `ignore` | 忽略这个字段，用户自己填 |
| `suggest` | 预填但允许用户修改 |
| `force` | 自动导入，缺失时不报错 |
| `require` | 自动导入，缺失时直接失败 |

大多数场景建议：

- `username`: `ignore`
- `displayname`: `suggest`
- `email`: `suggest`

## 故障排查

- 登录按钮点了后跳转错误：优先检查 provider 后台登记的 callback URL 是否和 `http.public_base` 实际推导出来的地址完全一致
- Google 返回 `redirect_uri_mismatch`：通常是 callback URL 少了路径前缀、端口不一致，或 `<provider-id>` 填错
- GitHub 回调后 400：通常是 `discovery_mode` 没关，或者 `subject` 仍然在用默认的 `{{ user.sub }}`
- OIDC discovery 失败：检查 `issuer` 是否和 provider 元数据里的 `issuer` 精确一致
- 用户资料导入为空：检查 `claims_imports` 模板引用的字段是否真的存在于 `id_token_claims` 或 `userinfo_claims`
