# Homeserver 配置

Pasion 需要与 Matrix homeserver 配合使用。目前仅支持 **Palpo**（1.136.0 或更高版本）。

## 配置 Palpo 使用 Pasion

在 Palpo 的配置文件中，启用委托认证（delegated authentication）：

```yaml
# Palpo homeserver.yaml 中的配置
experimental_features:
  msc3861:
    enabled: true
    issuer: https://auth.example.com/
    client_id: 0000000000000000000PALPO
    client_auth_method: client_secret_basic
    client_secret: "你的客户端密钥"
    admin_token: "你的管理员令牌"
    account_management_url: "https://auth.example.com/account/"
```

## Pasion 中的 Matrix 配置

在 Pasion 的配置文件中设置 homeserver 连接信息：

```yaml
matrix:
  homeserver: matrix.example.com
  secret: "你的共享密钥"
  endpoint: "https://matrix.example.com"
```

## 兼容层

Pasion 提供了一个兼容层，支持旧版 Matrix 客户端使用 `/_matrix/client/*/login` API 进行登录。这使得尚未支持 OIDC 的客户端仍然可以正常工作。

在 Pasion 配置中启用兼容层：

```yaml
matrix:
  homeserver: matrix.example.com
  secret: "你的共享密钥"
  endpoint: "https://matrix.example.com"
```

兼容层会自动为旧版登录创建 OAuth 2.0 会话，并将其映射到正确的用户。

## 故障排查

- **连接被拒绝** — 检查 Pasion 和 Palpo 之间的网络连通性，确保 `endpoint` 配置正确。
- **认证失败** — 确认 `client_secret` 和 `admin_token` 在 Pasion 和 Palpo 的配置中一致。
- **用户同步问题** — 确保 Pasion 拥有调用 Palpo 管理 API 的权限。
