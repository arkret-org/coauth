# Arkret 接口规则

适用于全部 `/_arkret/*` 接口的约束。完整操作目录以对应的
`arkret-spec/spec/v1/` 修订为准；本页记录 `coauth` 在本地强制执行的
规则。

## 第三方邀请

3PID 带外邀请不携带明文邮箱地址或手机号码。线上表示形式为
`offline_token`（`token_commitment`、`token_salt_id`、
`token_entropy_bits`）或 `lookup`（`lookup_table_ref`、`pepper_id`）。
领取流程与拒绝码见[账户生命周期](../account-lifecycle.md)。

## 策略检查

`POST /_arkret/self/policy/check` 接受 `PolicyCheckRequestBody`，返回的
`PolicyCheckOutcome` 包含：

- `bound_to`：该结论所绑定的请求字段，使调用方无法把它重放到另一个
  主体、动作或资源上。
- 三个来自 soland frontier 源的 frontier digest。frontier 拉取失败时
  发出「unknown frontier」哨兵值而非占位 digest，评估器据此给出相应
  保守的结论。
- 覆盖该结论的 DID 关联签名信封。

## DID 解析

`DidFullId` 拒绝 method 名段不落在 `^did:[a-z0-9]+:[^\s]+$` 内的标识
符。同一形态也作为数据库 `CHECK` 约束加在每个存储 DID 的列上，因此
绕过 handler 的值仍然无法落库。
