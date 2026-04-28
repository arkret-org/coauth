# 授权与会话

Pasion 使用 OAuth 2.0 和 OpenID Connect 标准来管理用户认证和授权。

## 会话类型

### 浏览器会话（Browser Session）

当用户通过 Web 界面登录时，Pasion 创建一个浏览器会话。该会话以加密 Cookie 的形式存储在用户的浏览器中。

### OAuth 2.0 会话

当 OAuth 2.0 客户端（如 Matrix 客户端）获得授权后，Pasion 创建一个 OAuth 2.0 会话。该会话关联了：

- 授权的用户
- 请求的客户端
- 授予的作用域（scope）
- 访问令牌和刷新令牌

### 兼容会话（Compat Session）

通过旧版 Matrix `/_matrix/client/*/login` API 创建的会话。这些会话在内部映射为 OAuth 2.0 会话。

## 授权流程（Grant Types）

### 授权码流程（Authorization Code Grant）

最常用的流程，适用于有用户界面的客户端（如 Element）：

1. 客户端将用户重定向到 Pasion 的授权端点
2. 用户登录并同意授权
3. Pasion 将用户重定向回客户端，附带授权码
4. 客户端使用授权码换取访问令牌

### 客户端凭据流程（Client Credentials Grant）

适用于服务间通信，无需用户参与：

1. 客户端使用自己的 `client_id` 和 `client_secret` 直接请求令牌
2. Pasion 验证客户端身份并颁发访问令牌

### 设备码流程（Device Code Grant）

适用于输入受限的设备（如智能电视）：

1. 设备向 Pasion 请求设备码
2. 用户在另一设备上访问验证 URL 并输入设备码
3. 用户在 Web 界面上完成登录和授权
4. 设备轮询 Pasion 获取访问令牌

## 访问令牌

访问令牌包含以下信息：

- **发行者（issuer）** — Pasion 的 URL
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
