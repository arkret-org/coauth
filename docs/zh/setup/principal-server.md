# Principal Server 配置

coauth 现在作为 Contrix Auth Server 运行。Soland 等下游 Principal Server 消费
OAuth/OIDC token 和 Contrix session grant；coauth 不再连接已退役的 delegated-auth
adapter。

## 配置 Soland Principal Server

在 `contrix.principal_servers` 中声明受信任的 Principal Server：

```yaml
contrix:
  principal_servers:
    - name: soland
      audience: https://soland.example.com/api
      endpoint: https://soland.example.com/
      did: did:web:soland.example.com
```

- `name`：面向运维的 Principal Server 标识。
- `audience`：该服务器验证 token/session grant 时使用的 audience。
- `endpoint`：通过 Contrix/OIDC discovery 发布的基础 URL。
- `did`：可选的 Principal Server DID。

## Discovery

coauth 通过标准 OpenID discovery 和 Contrix server describe 接口发布 Principal
Server 元数据：

- `/.well-known/openid-configuration`
- `/api/v1/server/describe`

服务启动后可以运行 `coauth doctor` 检查这些 discovery surface。
