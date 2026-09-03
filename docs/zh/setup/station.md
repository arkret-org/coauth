# Station 配置

coauth 作为所属 Station 的部署私有账号认证组件运行，位于 Station 发布的 Account
Authority surface 背后。Soland 等下游 Station 消费 OAuth/OIDC token 和 Arkret
session grant，但不会把 coauth 发现为独立 Arkret 服务角色。

## 配置 Soland Station

在 `arkret.stations` 中声明受信任的 Station：

```yaml
arkret:
  stations:
    - name: soland
      endpoint: https://soland.example.com/
      service_id: ak:did_core:webvh:<soland-scid>
      embedded_webvh_registration_bearer: ${SOLAND_WEBVH_REGISTRATION_BEARER}
```

- `name`：面向运维的 Station 标识。
- `endpoint`：通过 Arkret/OIDC discovery 发布的基础 URL。
- `service_id`：可选的显式身份 pin(`ak:did_core:webvh:<scid>`)。配置后优先级
  最高；省略时 pin 来自一次性 bootstrap 持久化的 trust enrollment(见下文)。
- `embedded_webvh_registration_bearer`：coauth 执行部署私有 Station-to-component
  调用的凭据；它不是公开服务角色凭据。

## 一次性 trust bootstrap

Station 的 DID/audience 绝不直接信任裸的 `/_arkret/describe` 响应。
coauth 在为某 Station audience 接受 token 或 session grant 之前，该
audience 必须由配置的 `service_id` 或持久化的 trust enrollment 固定。每个部署
执行一次：

```console
$ coauth station trust bootstrap --name soland
```

bootstrap 在线完整验证 Station 身份链（WebVH 历史、service-identity
绑定、resolution record 与 endpoint binding)，随后持久化验证后的 pin 并写入
审计。它是幂等的：身份未变时重复执行不会改动 pin。

Coauth HTTP 服务不会等待这项验证完成才开始监听。它会先发布 OIDC discovery、
公开 JWKS 和健康检查端点，让全新的 Station 能够取得 Account Authority 公钥；
后台验证成功前，业务路由统一返回 `503`，`/readyz` 也保持未就绪。独立 Worker
仍会在处理任务前执行同步 preflight。

发生合法的身份 genesis（新 SCID）后，显式替换 pin:

```console
$ coauth station trust replace --name soland \
    --expect-old ak:did_core:webvh:<old-scid> \
    --accept-new ak:did_core:webvh:<new-scid>
```

替换会在同一事务中吊销绑定旧 audience 的 session grant。
`coauth station trust revoke --name soland` 则整体移除 pin；此后服务在
重新存在 pin 之前拒绝提供服务。

## 部署私有 Account Authority 签名方

coauth 是所属 Station 的内部 Account Authority 进程。其签名凭据只属于部署内部：
它不是 Arkret service kind，不进入公开服务注册，也不通过 role-local Describe 或
peer discovery 暴露。客户端只从所属 Station 的
`auth_metadata.account_authority` 发现入口 URL。

签名密钥和任何进程本地标识均为实现细节，不得进入公开服务注册，不得作为服务 DID
发布，也不得用于 peer/federation 身份。恢复与轮换通过 Station 部署的私有密钥管理
流程完成。

## 服务间信任边界（部署内 S2S）

coauth 作为 Station 的私有账号认证组件，向 Station 发起两类**无 principal session**的
服务对服务读写，因此无法走需要 principal 鉴权的 `/_arkret/self/*` 协议面。它们是
落在 Station 自有 negative-space root 上的部署内 S2S 契约，依据
`service-http-binding.md` §2.1.4(b) —— **不是** v1 协议 operation：

| coauth 调用 | Station 端点 | Operation id | 时机 |
| --- | --- | --- | --- |
| 设备验签公钥目录查询 | `POST /_soland/gate/account/device-signing-keys/query` | `org.arkret.soland.gate.account.device_signing_keys.query` | 在 session-grant 刷新 / soft-logout 恢复时验证设备 holder proof |
| 协作 capability fanout | `POST /_soland/root/authz/capability-fanout` | `org.arkret.soland.root.authz.capability_fanout.submit` | 物化 coauth 签发的 `ak.capability.grant` / `ak.capability.revoke` |

两条边都用对应 `stations` 条目上配置的共享 bearer 鉴权：

`service_id` 是显式配置 pin，配置后优先级最高；省略时以
`coauth station trust bootstrap` 持久化的 trust enrollment 作为授权
pin。任何需要认证该 Station 的操作都必须存在二者之一，否则运行时
fail closed。`/_arkret/describe` 只用于能力与元数据校验，远端自报的 Describe
响应不能建立或替换 pin。

```yaml
arkret:
  stations:
    - name: soland
      # ...
      embedded_webvh_registration_bearer: "<共享 S2S 密钥>"
```

运维上该 bearer 是**信任边界密钥**：它赋予 coauth(认证 TCB)对 Station 的
目录读取与 capability fanout 权限。请按其它服务间凭据的同等节奏轮换，并确保
coauth↔Station 这一跳限于受信部署网络内。Station 把这些端点视作
部署内产品面，绝不暴露在其 `/_arkret/*` 协议根上。

## Discovery

coauth 只在 `/.well-known/openid-configuration` 发布标准 OpenID Provider discovery。
Arkret Describe 与 `auth_metadata.account_authority` 入口由所属 Station 发布；coauth
不暴露 role-local `/_arkret/describe` 端点。
