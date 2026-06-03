# Agent 运行时状态

当前 coauth 只暴露 agent principal 的内部 accountability-grant 签发面。
coauth 尚未暴露 `ck.account.agent_key_pair`，也尚未暴露
`ck.account.issue_session_grant` 的 agent 分支。

在这些路由真正接线前，客户端与 sodmin 不应把它们展示成可调用的 coauth
操作。`handlers/account/agents.rs` 中保留的拒绝 helper 与错误码矩阵只是
后续接线的单一语义来源，不代表当前存在公开 API。

## 已暴露接口

### `POST /_cokret/self/agents/{id}/accountability-grant`

这是内部 CXP-0008 接口，用于签发 accountability grant，将人类
controller DID、agent principal id，以及一组规范化的 `cx.agent.*`
能力绑定起来。

该接口仅用于服务到服务调用：

- 只接受 `cokret.principal_servers[].session_grant_introspection_bearer`
  中配置的 soland/sodmin 静态 bearer；
- 浏览器 session 与终端用户 OAuth token 会被拒绝；
- 路径 `{id}` 必须是 agent principal DID，并按单个 URL path segment 做 percent-encoding；
- `controller_did` 会在使用前规范化；
- 每个请求的 capability 都必须存在于本地 `cx.agent.*` capability registry。

成功后，coauth 会持久化 accountability grant，写入签名 admin audit 行，
并调度 soland fan-out job。同一个 controller、agent 与 capability
fingerprint 已存在 active grant 时会被拒绝；已被撤销的 controller DID 或
agent principal 也会被拒绝。

## 暂缓接口

### `ck.account.agent_key_pair`

该操作当前没有 coauth 路由。当前服务不会创建 pairing token，不会把 key
pair 绑定到 agent DID，也不会派发 `ck.account.agent_key_pair` 事件。

`pairing_request_expired`、`proof_invalid`、
`verification_method_principal_mismatch` 等失败码只描述未来 wire contract，
不能作为生产配对接口已存在的依据。

### `ck.account.issue_session_grant` 的 agent 分支

agent-principal 的 session-grant 签发分支当前没有 coauth 路由。现有
session-grant 端点不接受 agent-principal 签发请求，coauth 当前也不会在该
路径上评估 agent FSM 状态或 accountability-grant 新鲜度。

`agent_paused`、`agent_deactivated`、`accountability_grant_missing` 等失败码
在 agent 分支实现前不对外部客户端可用。

## 接线前置要求

暂缓接口对外暴露前，必须补齐路由 handler 与 focused tests，覆盖：

- proof 校验前显式绑定 agent DID 与 verification method；
- pairing token 生命周期与重放处理；
- paused/deactivated agent FSM 的 fail-closed 闸门；
- durability-backed accountability-grant 新鲜度检查；
- 只有在 handler 实际可用后，才更新 discovery 与文档发布新路由。
