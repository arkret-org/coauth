# Agent 运行时（Agent Runtime）

Agent 运行时是 coauth 暴露给 **Agent Principal** 的接口面。Agent
Principal 与人类 Principal 是不同的主体类型：它有自己的 DID、自己的密钥
对，以及一个有限状态生命周期（Active → Paused → Deactivated），用于在
每一次签发会话凭证（session grant）前进行准入判断。

本章覆盖两个 coauth 侧的协议操作，以及当配对失败或镜像状态过期时你会
看到的错误码矩阵。

## `cx.account.agent_key_pair`

将 agent 的 DID 与一对新生成的密钥绑定到所属人类 Principal 名下。配对
流程：

```text
[人类 Principal]                  [coauth]                       [agent 客户端]
   |                                  |                                |
   |  POST agent_key_pair (proof)     |                                |
   |--------------------------------->|                                |
   |                                  | 解析 agent DID                  |
   |                                  | 校验 proof 字节（JCS）          |
   |                                  | 校验 verification_method        |
   |                                  | 打开配对窗口（10 min）          |
   |                                  |                                |
   |                                  |  pairing token                  |
   |                                  |------------------------------->|
   |                                  |                                |
   |                                  |  agent 对 key_pair 签名         |
   |                                  |<-------------------------------|
   |                                  |                                |
   |                                  | 将 key_pair 绑定到 agent DID    |
   |                                  | 派发 cx.account.agent_key_pair  |
```

协议失败模式：

- **`pairing_request_expired`** — 10 分钟配对窗口超时。人类 Principal 必
  须重新发起。常见根因：agent 客户端时钟漂移 >5 分钟；先检查双端 NTP。
- **`proof_invalid`** — 提交的 proof 与 coauth 重新计算的规范字节摘要不
  一致。通常是客户端 JSON 序列化漂移：取原始 payload 与 JCS 字节做 diff。
- **`verification_method_principal_mismatch`** — proof 中的
  `verification_method` 解析到的 DID 与所声称的 agent Principal 不一致。
  原因可能是 DID 文档配置错误、密钥轮换未完成，或恶意调用。直接拒绝并
  归档审计；不要盲目重试。

配对成功后会派发 `cx.account.agent_key_pair` 事件，payload 包含 agent
的 DID、签发的密钥指纹、规范化 proof 摘要。下游服务（soland）将该事件
视作 agent 绑定到该人类 Principal 的唯一凭证。

## `cx.account.issue_session_grant` — Agent 分支

当一个 agent 来请求 session grant 时，coauth 在普通的人类 session 校验
之外，额外执行以下闸门：

1. 解析 agent Principal 的 FSM 状态（来自 soland 的 `agent_state` cell，
   本地镜像以保证新鲜度）。
2. 若状态为 `Paused`，拒绝并返回 `agent_paused`。**不签发** grant；
   调用方必须先恢复 agent，再重试。
3. 若状态为 `Deactivated`，拒绝并返回 `agent_deactivated`。终态——除非
   在新的 agent DID 下重新绑定，否则不可恢复。
4. 若在签发时，人类 Principal 到该 agent 的
   `accountability_grant` 尚不存在或已撤销，拒绝并返回
   `accountability_grant_missing`。常见原因：人类 Principal 的可问责性
   授权在过期的 agent token 仍在流转时被撤销。

### 错误码矩阵

| 错误 | 触发条件 | 恢复手段 |
|---|---|---|
| `agent_paused` | Agent FSM = Paused | 运维通过 soland 的 POST /agents/{id}/resume 恢复，再重试 |
| `agent_deactivated` | Agent FSM = Deactivated（终态） | 在新 DID 下重新绑定 agent；旧 agent 无法救活 |
| `accountability_grant_missing` | 签发时缺少匹配的 `accountable_to` 链 | 由人类 Principal 重新签发 accountability grant，再重试 |
| `pairing_request_expired` | 10 min 配对窗口超时 | 重新发起 `cx.account.agent_key_pair` |
| `proof_invalid` | 配对 proof 规范字节不匹配 | 检查客户端序列化；重新提交 |
| `verification_method_principal_mismatch` | 配对 `verification_method` 解析到的 DID 不一致 | 修正 DID 文档；重新提交 |

## 撤销新鲜度窗口（Revocation Freshness Window）

Agent FSM 与 accountability grant 链由 soland 持有，但镜像进 coauth 以
避免每次 session 签发都做同步上游调用。镜像默认的新鲜度窗口为 60s，可
通过 `auth.agent.revocation_freshness_window` 调整。

如果一次状态变更（pause / deactivate / 撤销 accountability grant）在
`t = 0` 时刻于 soland 落盘，coauth **必须** 拒绝基于 `t - 窗口` 之前的
陈旧数据签发 grant。

机制：

- 每条镜像记录携带 coauth 本地时钟刷新时刻的 `mirrored_at`。
- 签发评估在读取镜像后会校验 `now - mirrored_at <= window`。若已陈旧，
  coauth 会先同步刷新镜像再决策。
- 窗口内的同步刷新失败按 fail-closed 处理——拒绝 grant，对应错误码为
  `agent_*` 或 `accountability_grant_missing`，并在日志中留下供运维定位
  的失败证据。

调整窗口时的权衡：

- 窗口越小 → 撤销传播越紧、上游流量越多。
- 窗口越大 → 传播保证越松、上游负载越低。
- 严格拒绝（strict-reject）的部署姿态（见
  [部署强化](./deployment_hardening.md)）通常会把窗口固定为 ≤ 30s。
