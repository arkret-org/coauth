# 升级到 Round R4

Round R4 收尾了 `coauth` 与 Cokret 协议在 2026-05-20 协议评
审中确定的工作。它对直接消费 Cokret 账户、身份、邀请或策
略接口的客户端与下游服务而言是破坏性更新。OIDC/OAuth 端点
仍保持原有的兼容性策略。

在启用包含 R4 变更的构建之前，请先阅读本页。

## 破坏性接口

- **3PID OOB 邀请** 不再携带明文邮箱地址或手机号码。线上
  表示形式为 `offline_token`（`token_commitment`、
  `token_salt_id`、`token_entropy_bits`）或 `lookup`
  （`lookup_table_ref`、`pepper_id`）。
- **邀请领取** 使用双证明链：验证 3PID 的验证服务证明，加
  上由邀请人 actor key 签名的主体证明。
- **`ck.cross_signing.publish`** 现已转为 compare-and-swap。
  发布者必须读取当前 generation 并提交
  `expected_previous_generation`；被接受的 generation 仅前
  进一格。
- **`/policy/check` v2** 使用 `PolicyCheckRequestBody`，并返回
  带有 `bound_to`、frontier digest 与 DID 关联签名信封的
  `PolicyCheckOutcome`。
- **`identity_link`** 负载同时绑定 `realm_id` 与
  `trust_domain`。
- **DID 解析** 拒绝不在收紧后的
  `^did:[a-z0-9]+:[^\s]+$` 形态中的 method 名。

完整的未发布 R4 条目见
[`CHANGELOG.md`](../../CHANGELOG.md)。

## Trust domain 轮换

`cokret.trust_domain` 是每一条 `ck.cross_signing.reset` 证明
的规范 transcript 的一部分。变更该值会令使用旧 trust domain
签发的 reset 证明失效。

轮换前：

1. 记录当前配置值，并确认其与 `/_cokret/describe`
   返回的一致。
2. 暂停或拒绝以旧值签发、尚未完成的 cross-signing reset
   批准请求。
3. 对数据库做快照，并将旧配置与该快照一起保存。
4. 与 Principal Server 运维人员协调，使其在切换之后拒绝
   过期 reset 证明。

轮换过程中：

1. 在 `cokret.trust_domain` 中写入新值。
2. 重启一个 `coauth` 副本，确认
   `/_cokret/describe` 公布了新值。
3. 滚动重启其余副本。
4. 通过设备恢复流程重新签发 reset 证明。受影响的证明族
   包括 `principal_signing`、`recovery_unlock`、
   `device_quorum` 与 `trusted_recovery_service`。
5. 在新证明可用之后再发布新的 cross-signing generation。

不要把旧 reset 证明重新喂给新的 trust domain。它们必须失败，
因为其规范 transcript 是为另一个部署作用域签名的。

## 邀请领取迁移

需要领取 3PID 邀请的客户端必须同时发送：

- 由配置的 3PID 验证服务签名的验证服务证明；以及
- 由邀请人 actor key 签名、并与验证证明 `jti` 关联的主体
  证明。

过期证明会返回 `proof_expired`。被重用的验证证明 `jti` 会被
判定为重放并拒绝。由非邀请人 actor 出示的主体证明会被以
`subject_did_mismatch` 拒绝。

## 回滚

R4 的 schema migration 仅前向。如必须回退升级，应恢复升级
前的数据库快照与匹配的升级前配置。不要假设来回切换
`trust_domain` 可以安全地复活在失败升级期间产生的证明。
