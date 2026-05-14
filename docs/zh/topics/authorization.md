# 授权与会话

`coauth` 负责认证用户和客户端，然后签发 OAuth/OIDC token 或 Contrix
session grant，供下游服务验证。

## 会话类型

### 浏览器会话

用户通过 Web UI 登录后，`coauth` 会创建浏览器会话，并以加密 Cookie 保存。

### OAuth 会话

OAuth 会话在客户端完成授权流程后创建，关联以下信息：

- 被授权的用户（如果该 grant 绑定用户）
- 请求授权的客户端
- 已授予的 scope
- access token 与 refresh token

### Contrix Session Grant

Principal Server 应验证 `cx.session.grant` 来执行下游账号和设备访问。grant payload
包含 issuer service DID、subject principal DID、service account ID、可选 device
ID、audience、scope、expiry、revocation reference 以及 proof block。

`POST /api/v1/session-grants/introspect` 接受 grant ID 或 signed grant JWT，并可附带
audience。响应只返回 `active`、标准状态（`active`、`revoked`、`expired`、`locked`、
`suspended`、`audience_mismatch`、`not_found`）和非敏感元数据，不返回已存储 JWT、
refresh token、session private key、handle 或 claim payload。

## Grant Types

### Authorization Code

适合有浏览器交互能力的客户端。客户端把用户重定向到 `coauth`，拿到授权码后再换取
token。

### Device Authorization

适合不方便承载浏览器 redirect 的设备或 CLI。设备展示 code，用户在另一台设备确认，
客户端轮询直到 token 签发完成。

### Client Credentials

适合服务间自动化。客户端以自身身份认证，不需要用户浏览器会话。

## Access Token

Access token 对客户端是不透明字符串，`coauth` 在服务端保存 token 元数据：

- subject
- client
- granted scopes
- expiry
- revocation state

用户、管理员或授权客户端都可以通过撤销端点撤销 token。

## Personal Session

管理员可以签发 personal access token，用于自动化或委托用户操作。它们携带预定义
scope 和过期时间，可通过 admin API regenerate 或 revoke。
