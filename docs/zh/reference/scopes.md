# OAuth 2.0 作用域

`coauth` 现在把 Contrix scope 视为主产品接口。Legacy Matrix / Palpo scope 仍然
保留给 compatibility adapter，但不再是推荐的集成路径。

## 主路径上的 coauth / Contrix scope

### `openid`

请求 OpenID Connect `id_token`，并允许访问 userinfo endpoint。对 `chask`
这样的交互式 OIDC client 来说，它仍然是基础 scope。

### `email`

在部署中存在该数据时，请求用户的已验证邮箱地址。通常与 `openid` 搭配使用。

### `urn:coauth:admin`

coauth 的 canonical admin scope，用于访问 coauth admin API，也是现阶段最稳定的
管理权限入口。

### `urn:contrix:admin:*`

Contrix admin capability family。当前 `coauth` 会接受整个 wildcard family，以及
`urn:contrix:admin:<capability>` 前缀形式的管理权限。

对于 `sodmin` 或内部自动化等 Contrix-native 管理集成，优先使用这个命名空间。

### `urn:contrix:client:*`

Contrix client capability family，面向 `chask` 这类第一方或受信任的 Contrix client。

当前它主要作为粗粒度 capability family 被发布；后续可以在策略和客户端约定中继续细化。

### `urn:contrix:principal-server:*`

Principal Server capability family，面向受信任的 Principal Server 集成，用于表达
比通用 OIDC 登录更明确的能力边界。

### `urn:contrix:principal-server:session.bind`

表示请求或描述“为当前认证后的浏览器会话签发短时 Contrix session grant”的能力。
当 `coauth` 为受信任的 Principal Server 生成 session grant 时，会使用这个 scope。

## 与 scope 一起暴露的 Contrix claim

在适用时，ID token、userinfo 响应和 introspection 响应会暴露以下 Contrix claim：

- `org.contrix.principal_did`
- `org.contrix.device_id`
- `org.contrix.session_id`

只有当会话确实绑定了设备标识时，`device_id` 才会出现。

## Legacy compatibility scope

### `urn:matrix:client:api:*` 和 `urn:matrix:org.matrix.msc2967.client:api:*`

这是 legacy Matrix client API access scope，属于 compatibility adapter 路径，不应再
作为新的 Contrix 部署的主 scope contract。

### `urn:matrix:client:device:[device id]` 和 `urn:matrix:org.matrix.msc2967.client:device:[device id]`

这是 legacy Matrix device-binding scope，会把设备 ID 直接编码进 scope token，目前
仍然被兼容路径识别。

### `urn:palpo:admin:*`

这是 legacy Palpo admin scope family，只有在 `coauth` 仍被用于旧 Palpo / Matrix
delegated-auth bridge 时才相关。

### `urn:mas:admin`

这是为了向后兼容保留的 legacy admin scope。旧 token 仍可继续使用，但新的集成应迁移到
`urn:coauth:admin` 或 `urn:contrix:admin:*`。

## 策略说明

- OIDC discovery 会发布主路径上的 Contrix scope family 和 claim。
- `urn:coauth:admin` 是现有 admin API 的稳定 scope。
- `urn:contrix:admin:*` 是 Contrix-native 的管理命名空间。
- `urn:contrix:principal-server:session.bind` 用于受信任 Principal Server 的
  session grant。
- Matrix / Palpo scope 应视为 legacy compatibility affordance，而不是新工作的默认
  scope registry。
