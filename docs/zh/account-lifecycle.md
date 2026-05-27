# 账户生命周期

`coauth` 将本地账户状态与邀请状态分开管理。本地账户状态决定
认证后的账户是否可以继续使用服务；第三方邀请状态决定带外邀
请是否仍可被领取。

## 本地账户状态

管理 API 将账户状态暴露为以下三种之一：

- `active`：账户可以登录并使用启用的账户功能。
- `locked`：账户存在，但交互访问被阻止，直到管理员或恢复流
  程将其解锁。
- `disabled`：账户被停用，不应再被视为可用的登录主体。

这些状态会出现在管理员账户记录中，供运营动作、审计视图和
UI 门禁使用。

## 第三方邀请领取流程

Round R4 邀请领取使用 `cx.schema.invite.v1` 的
`third_party_invite` 形态。邮箱、手机号等明文 3PID 值不再在
网络中传输。

邀请从 `pending` 开始，然后会进入以下五种终态之一：

```text
pending
  -> claimed
  -> send_failed
  -> revoked_by_capability_loss
  -> revoked_by_inviter_left
  -> invalidated_by_rate_limit
```

五种终态都是最终状态。一旦邀请进入终态，`coauth` 会在
24 小时内安排本地 salt / pepper 的零化清除，避免邀请被重放。

## 邀请的传输模式

`offline_token` 模式携带高熵 token 承诺：

- `token_commitment`：明文 token 加 salt 的 SHA-256 承诺。
- `token_salt_id`：不透明的本地 salt 标识符。
- `token_entropy_bits`：至少 128 位。

`lookup` 模式携带不透明的查询引用：

- `lookup_table_ref`：本地查询表引用。
- `pepper_id`：不透明的服务端 pepper 标识符。

在 `lookup` 模式下，连续三次查询失败会将邀请置为
`invalidated_by_rate_limit`。

## 领取证明链

一次成功的 `cx.invite.claim` 需要两个相互关联的证明：

1. **验证服务证明**：由受信任的 3PID 验证服务签名的 JWT。
   `coauth` 会校验 issuer、audience、subject、过期时间、
   生效时间、nonce、签名和 `jti` 重放。
2. **主体证明**：由邀请人 actor key 签名的 JWS，绑定验证
   证明的 `jti`、3PID 哈希、被邀请人 promise DID 以及过期时
   间。提交领取请求的 actor 必须与邀请人 DID 一致。

已接受的验证证明 `jti` 会被记忆直至其过期。带有相同有效
`jti` 的二次领取会被识别为重放并拒绝。

## 拒绝码

邀请领取失败会映射到稳定的机读代码：

| 代码 | HTTP 状态 | 含义 |
| --- | --- | --- |
| `verification_proof_invalid` | 401 | 验证服务证明格式错误、不可验证、claim 不正确，或重放了存活的 `jti`。 |
| `subject_proof_invalid` | 401 | 主体证明格式错误、不可验证，或与验证证明未关联。 |
| `proof_expired` | 410 | 任一证明已过期。 |
| `subject_did_mismatch` | 403 | 主体证明中的邀请人 DID 与提交领取的 actor 不一致。 |

操作者侧的迁移清单请参见
[升级到 Round R4](./upgrade-to-r4.md)。
