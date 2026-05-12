# OAuth 2.0 作用域

`coauth` 当前支持 coauth 与 Contrix 命名空间下的 scope。

## `openid`

请求 OpenID Connect `id_token`，并允许访问 userinfo endpoint。这是 `yougen`
等交互式 OIDC client 的基础 scope。

## `email`

请求用户已验证的邮箱地址。通常与 `openid` 一起使用。

## `urn:coauth:admin`

标准 coauth 管理 scope。它授予 coauth admin API 访问权限，是稳定管理工具的首选。

## `urn:contrix:admin:*`

Contrix 管理能力族。`coauth` 接受 wildcard scope，也接受
`urn:contrix:admin:<capability>` 前缀作为管理权限。

这个命名空间适合 `sodmin` 等 Contrix-native 管理集成。

## `urn:contrix:client:*`

面向一方或受信任 Contrix client 的能力族。

## `urn:contrix:client:device:[device id]`

Contrix 设备绑定 scope。它把 OAuth session 与下游 Principal Server 使用的
client device identifier 关联起来。

## `urn:contrix:principal-server:*`

Principal Server 能力族。这个命名空间用于需要比普通 OIDC 登录更细粒度授权的
受信任 Principal Server 集成。

## `urn:contrix:principal-server:session.bind`

请求或描述为已认证浏览器会话签发短时 Contrix session grant 的能力。`coauth`
给受信任 Principal Server 签发 session grant 时使用这个 scope。

## Contrix Claims

在适用场景下，ID token、userinfo response 和 introspection response 可以暴露：

- `org.contrix.principal_did`
- `org.contrix.device_id`
- `org.contrix.session_id`

只有当 session 绑定到设备标识时才会出现 `device_id`。
