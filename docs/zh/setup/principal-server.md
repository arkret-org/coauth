# Principal Server 配置

coauth 现在作为 Arkret Auth Server 运行。Soland 等下游 Principal Server 消费
OAuth/OIDC token 和 Arkret session grant；coauth 不再连接已退役的 delegated-auth
adapter。

## 配置 Soland Principal Server

在 `arkret.principal_servers` 中声明受信任的 Principal Server：

```yaml
arkret:
  principal_servers:
    - name: soland
      audience: did:webvh:<scid>:soland.example.com:webvh:service
      endpoint: https://soland.example.com/
      did: did:webvh:<scid>:soland.example.com:webvh:service
```

- `name`：面向运维的 Principal Server 标识。
- `audience`：该服务器验证 token/session grant 时使用的 service DID audience。
- `endpoint`：通过 Arkret/OIDC discovery 发布的基础 URL。
- `did`：可选的 Principal Server DID。

## 服务间信任边界（部署内 S2S）

coauth 以 Auth Server 角色对 Principal Server 发起两类**无 principal session**的
服务对服务读写，因此无法走需要 principal 鉴权的 `/_cokret/self/*` 协议面。它们是
落在 Principal Server 自有 negative-space root 上的部署内 S2S 契约，依据
`service-http-binding.md` §2.1.3(b) —— **不是** v1 协议 operation：

| coauth 调用 | Principal Server 端点 | Operation id | 时机 |
| --- | --- | --- | --- |
| 设备验签公钥目录查询 | `POST /_soland/gate/account/device-signing-keys/query` | `org.arkret.soland.gate.account.device_signing_keys.query` | 在 session-grant 刷新 / soft-logout 恢复时验证设备 holder proof |
| 协作 capability fanout | `POST /_soland/root/authz/capability-fanout` | `org.arkret.soland.root.authz.capability_fanout.submit` | 物化 coauth 签发的 `ck.capability.grant` / `ck.capability.revoke` |

两条边都用对应 `principal_servers` 条目上配置的共享 bearer 鉴权：

```yaml
arkret:
  principal_servers:
    - name: soland
      # ...
      embedded_webvh_registration_bearer: "<共享 S2S 密钥>"
```

运维上该 bearer 是**信任边界密钥**：它赋予 coauth(认证 TCB)对 Principal Server 的
目录读取与 capability fanout 权限。请按其它服务间凭据的同等节奏轮换，并确保
coauth↔Principal Server 这一跳限于受信部署网络内。Principal Server 把这些端点视作
部署内产品面，绝不暴露在其 `/_cokret/*` 协议根上。

## Discovery

coauth 通过标准 OpenID discovery 和 Arkret server describe 接口发布 Principal
Server 元数据：

- `/.well-known/openid-configuration`
- `/_cokret/describe`

服务启动后可以运行 `coauth doctor` 检查这些 discovery surface。
