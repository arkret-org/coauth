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
      endpoint: https://soland.example.com/
      service_id: ak:did_core:webvh:<soland-scid>
      embedded_webvh_registration_bearer: ${SOLAND_WEBVH_REGISTRATION_BEARER}
```

- `name`：面向运维的 Principal Server 标识。
- `endpoint`：通过 Arkret/OIDC discovery 发布的基础 URL。
- `service_id`：可选的显式身份 pin(`ak:did_core:webvh:<scid>`)。配置后优先级
  最高；省略时 pin 来自一次性 bootstrap 持久化的 trust enrollment(见下文)。
- `embedded_webvh_registration_bearer`:Coauth 向该 Provider 查询或幂等注册自身
  service identity 的部署级凭据。

## 一次性 trust bootstrap

Principal Server 的 DID/audience 绝不直接信任裸的 `/_arkret/describe` 响应。
coauth 在为某 Principal Server audience 接受 token 或 session grant 之前，该
audience 必须由配置的 `service_id` 或持久化的 trust enrollment 固定。每个部署
执行一次：

```console
$ coauth principal-server trust bootstrap --name soland
```

bootstrap 在线完整验证 Principal Server 身份链（WebVH 历史、service-identity
绑定、resolution record 与 endpoint binding)，随后持久化验证后的 pin 并写入
审计。它是幂等的：身份未变时重复执行不会改动 pin。

发生合法的身份 genesis（新 SCID）后，显式替换 pin:

```console
$ coauth principal-server trust replace --name soland \
    --expect-old ak:did_core:webvh:<old-scid> \
    --accept-new ak:did_core:webvh:<new-scid>
```

替换会在同一事务中吊销绑定旧 audience 的 session grant。
`coauth principal-server trust revoke --name soland` 则整体移除 pin；此后服务在
重新存在 pin 之前拒绝提供服务。

## coauth 自身的 service identity

coauth 是 A 类服务：它自行生成并持有自身 service DID 的签名私钥，只把公开的
`did:webvh` 日志托管在 Provider（即上面配置的 Principal Server）上。运行时的
身份来源只有两个：

- 本地 `service_identity` 表中已验证的记录；
- Provider 上按注册键 `{service_kind: auth_server, public_base}` 建立的稳定 mapping。

配置里**不写** coauth 自己的 `service_id`。`embedded_webvh_registration_bearer`
只是访问 Provider 的部署级传输凭据，不构成身份；真正的控制权在 key backend 里
kid 为 `coauth-service-identity-v1` 的 Ed25519 私钥上。

### Provider 证明的验证

Provider 每次返回的 `ServiceRegistrationOutcome` 都带一份 registration receipt。
coauth 在写入任何本地状态之前先完整验证它的 Provider 证明：

1. 从 Provider 的 `/_arkret/describe` 取得它当前的 DID；配置了
   `principal_servers[].service_id` pin 时，describe 声明的 `service_id` 必须逐字等于该 pin；
2. 从该 DID 自身派生 `did.jsonl` 地址，完整验证 Provider 的方法原生历史（SCID 派生、条目哈希链、
   每条条目的签名与轮换授权），并要求验证出的 head 等于 describe 声明的版本；
3. 要求 `project(did)` 等于 receipt 里的 `provider_service_id`，且 receipt
   `verification_method` 的裸 controller DID 逐字等于该 `did`；
4. 要求该 method 在 receipt `issued_at` 时点属于 Provider DID Document 的 `assertionMethod`；
5. 实际验证 receipt 的 Ed25519 detached JWS。

传输凭据、mTLS、HTTPS 成功或 proof 结构自洽都**不能**替代这一步。任何一条不成立都是
`service_registration_restore_failed`，运行时落到 `503 faulted` 且本地零写入；此时
应排查 Provider 的 describe 与其托管的 `did.jsonl` 是否属于同一个身份、是否与 pin 一致。
Provider 的 describe 或 `did.jsonl` 暂时不可达时不会误判为失败：没有本地记录时进入
`WaitingProvider`，已有已验证记录时进入 `DegradedStored`，两者都持续重试。

### 本地状态丢失后的自动恢复

换库、清库或恢复到一个空库之后，coauth 仍持有该 Ed25519 私钥，但丢掉了
`service_identity` 记录。此时启动会自动回填原 DID，不需要任何人工步骤：

1. 按注册键查询 Provider，命中既有注册；
2. 校验返回的 DID Document 与 registration receipt 同本地签名/控制密钥的绑定；
3. 从 DID 自身派生出的 `did.jsonl` 地址拉取方法原生历史，并完整验证链（SCID 派生
   与条目签名）；
4. 要求首条 inception 条目的规范摘要等于 receipt 中 Provider 签署的
   `log_head_digest`；
5. 要求该条目的 `updateKeys[0]` 等于本进程从 key backend 派生出的控制密钥。

第 5 步是控制权证明：只有持有本地 service-identity 私钥的进程才能通过，因此属于
**另一个控制根**的注册永远不会被收养，而是 fail closed 为
`service_identity_key_mismatch`。

Provider 侧的注册**不需要**人工清理。反过来，人工删掉 Provider 注册会让 coauth
铸出一个新 DID，使此前签发的凭据与派生身份全部失根——不要这么做。

Provider 或其托管的 `did.jsonl` 暂时不可达时，运行时进入 `WaitingProvider` 并持续
重试，discovery 返回 `503 service_identity_unavailable` 与 `Retry-After`，恢复后
无需重启。

key backend 与数据库同时丢失则无法恢复，这是协议要求的密钥自持边界：Provider
是托管方而非控制者，不持有也无法代持 coauth 的私钥。

## 服务间信任边界（部署内 S2S）

coauth 以 Auth Server 角色对 Principal Server 发起两类**无 principal session**的
服务对服务读写，因此无法走需要 principal 鉴权的 `/_arkret/self/*` 协议面。它们是
落在 Principal Server 自有 negative-space root 上的部署内 S2S 契约，依据
`service-http-binding.md` §2.1.4(b) —— **不是** v1 协议 operation：

| coauth 调用 | Principal Server 端点 | Operation id | 时机 |
| --- | --- | --- | --- |
| 设备验签公钥目录查询 | `POST /_soland/gate/account/device-signing-keys/query` | `org.arkret.soland.gate.account.device_signing_keys.query` | 在 session-grant 刷新 / soft-logout 恢复时验证设备 holder proof |
| 协作 capability fanout | `POST /_soland/root/authz/capability-fanout` | `org.arkret.soland.root.authz.capability_fanout.submit` | 物化 coauth 签发的 `ak.capability.grant` / `ak.capability.revoke` |

两条边都用对应 `principal_servers` 条目上配置的共享 bearer 鉴权：

`service_id` 是显式配置 pin，配置后优先级最高；省略时以
`coauth principal-server trust bootstrap` 持久化的 trust enrollment 作为授权
pin。任何需要认证该 Principal Server 的操作都必须存在二者之一，否则运行时
fail closed。`/_arkret/describe` 只用于能力与元数据校验，远端自报的 Describe
响应不能建立或替换 pin。

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
部署内产品面，绝不暴露在其 `/_arkret/*` 协议根上。

## Discovery

coauth 通过标准 OpenID discovery 和 Arkret server describe 接口发布 Principal
Server 元数据：

- `/.well-known/openid-configuration`
- `/_arkret/describe`

服务启动后可以运行 `coauth doctor` 检查这些 discovery surface。
