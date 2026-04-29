# Legacy 兼容路由

Contrix-native 部署应使用标准 OIDC 和 coauth API。剩余 legacy 路由只用于旧链接跳转或
显式兼容场景，不应作为新集成入口。

## 仍然支持

以下账户页面链接仍作为旧书签和旧用户流程的 redirect 保留：

- `/account`
- `/account/password/change`
- `/account/password/recovery`

OAuth 2.0 和 OIDC endpoint 仍是受支持的集成入口：

- `/.well-known/openid-configuration`
- `/oauth2/auth`
- `/oauth2/token`
- `/oauth2/device`
- `/oauth2/revoke`
- `/oauth2/introspect`
- `/oauth2/userinfo`
- `/oauth2/registration`

Contrix-native 服务集成应使用 `/api/v1/server/describe`、`/api/v1/identity/*`、
`/api/v1/directory/*` 和 `/api/v1/session-grants`。

## 当前生产路径已移除

当前默认 router 中的 `compat` HTTP resource 是 no-op，因此生产路径不会服务以下
Matrix / Palpo compatibility endpoint：

- `/_matrix/client/*/login`
- `/_matrix/client/*/logout`
- `/_matrix/client/*/refresh`
- `/_matrix/client/unstable/org.matrix.msc2965/auth_metadata`
- `/_palpo/client/*`
- `/_palpo/mas/*`

CLI/admin device authorization 应使用 `/.well-known/openid-configuration` 做 discovery，
并使用 `/oauth2/device`。Matrix 和 Palpo scope 只属于 legacy adapter 输入；新的
Contrix client 应按需请求 `urn:coauth:admin`、`urn:contrix:client:*`、
`urn:contrix:admin:*` 或 `urn:contrix:principal-server:*`。
