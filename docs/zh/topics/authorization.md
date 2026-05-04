# 授权与会话

`coauth` 使用 OAuth 2.0、OpenID Connect 和 Contrix session grant 来管理账号认证、客户端授权和 Principal Server 会话验证。

## 会话类型

### 浏览器会话（Browser Session）

当用户通过 Web 界面登录时，`coauth` 创建一个浏览器会话。该会话以加密 Cookie 的形式存储在用户的浏览器中。

### OAuth 2.0 会话

当 OAuth 2.0 客户端获得授权后，`coauth` 创建一个 OAuth 2.0 会话。该会话关联了：

- 授权的用户
- 请求的客户端
- 授予的作用域（scope）
- 访问令牌和刷新令牌

### 兼容会话（Compat Session）

通过旧版 Matrix `/_matrix/client/*/login` API 创建的会话。这些会话在内部映射为 OAuth 2.0 会话，只属于 legacy compatibility adapter。

### Contrix Session Grant

Principal Server 应验证 `cx.session.grant`，而不是把 legacy scope 当作 Contrix capability。session grant payload 包含 issuer service DID、subject principal DID、service account ID、device ID、audience、scope、expiry、revocation reference，以及带签名算法、key ID、canonical payload hash 和 hash algorithm 的 proof block。

`POST /api/v1/session-grants/introspect` 接受 grant ID 或 signed grant JWT，并可附带 audience。响应只返回 `active`、标准状态码（`active`、`revoked`、`expired`、`locked`、`suspended`、`audience_mismatch`、`not_found`）和非敏感元数据，不返回已存储 JWT、refresh token、session private key、handle 或 claim payload。

## 授权流程（Grant Types）

### 授权码流程（Authorization Code Grant）

最常用的流程，适用于有用户界面的客户端（如 Element）：

1. 客户端将用户重定向到 `coauth` 的授权端点
2. 用户登录并同意授权
3. `coauth` 将用户重定向回客户端，附带授权码
4. 客户端使用授权码换取访问令牌

### 客户端凭据流程（Client Credentials Grant）

适用于服务间通信，无需用户参与：

1. 客户端使用自己的 `client_id` 和 `client_secret` 直接请求令牌
2. `coauth` 验证客户端身份并颁发访问令牌

### 设备码流程（Device Code Grant）

适用于输入受限的设备（如智能电视）：

1. 设备向 `coauth` 请求设备码
2. 用户在另一设备上访问验证 URL 并输入设备码
3. 用户在 Web 界面上完成登录和授权
4. 设备轮询 Pasion 获取访问令牌

## 访问令牌

访问令牌包含以下信息：

- **发行者（issuer）** — `coauth` 的 URL 或 service DID
- **主体（subject）** — 用户标识
- **作用域（scope）** — 授权的权限范围
- **过期时间（expiry）** — 令牌的有效期

令牌的有效期可以在配置文件中设置：

```yaml
matrix:
  access_token_ttl: 300  # 秒（默认 5 分钟）
```

## 令牌撤销

访问令牌可以通过以下方式撤销：

- 用户在账户管理页面手动结束会话
- 管理员通过管理 API 终止会话
- 客户端调用令牌撤销端点
