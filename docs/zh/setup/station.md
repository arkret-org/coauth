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
      trust_domain: ak:trust_domain:soland.example.com
      internal_authority_shared_secret_file: /run/secrets/soland_internal_authority_shared_secret
      embedded_webvh_registration_bearer: ${SOLAND_WEBVH_REGISTRATION_BEARER}
```

- `name`：面向运维的 Station 标识。
- `endpoint`：通过 Arkret/OIDC discovery 发布的基础 URL。
- `trust_domain` 与 `internal_authority_shared_secret{_file}`：部署内固定通道的
  显式边界；文件在启动时只读取一次。
- `embedded_webvh_registration_bearer`：coauth 执行部署私有 Station-to-component
  调用的凭据；它不是公开服务角色凭据。

## 自动验证与耐久绑定

首次启动不要求管理员知道 Station service ID，也不要求执行初始化命令。coauth 从
配置的 exact endpoint 在线完整验证 WebVH 历史、service-identity binding、
authenticated resolution、role 与 endpoint binding，随后原子持久化 pin、防回滚
floor 和审计记录。裸 `/_arkret/describe` 响应或 shared secret 单独都不能建立身份；
并发实例只有验证出完全相同 tuple 才能幂等收敛。

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
下一轮自动完整验证重新建立 binding 之前拒绝提供服务。

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

运行时只使用已经完整验证并耐久保存的 Station binding。endpoint 变化只有在同一
service core 证明连续、非回退的 WebVH history 后才会自动 CAS 更新；新 core/genesis
必须执行上面的显式 replace。shared secret 只认证该 binding 对应的配置槽，不能建立
或替换 pin。

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
