# Agent 运行时状态

coauth 通过 canonical Arkret gate 暴露 Agent key pairing 与 Agent
SessionGrant 分支。客户端入口继续使用 controller 的 sender-constrained
session 合同。

拆分部署中，Account Authority 必须把 Agent 当前投影查询与 exact pairing
command 委托给明确配置的 owning Station。该委托使用 owning Station DID 中授权的
`#account-authority` RFC 9421 service signature，并绑定 method、exact target、
operation、source/destination service id、两侧 trust domain，以及有 body 时的
`Content-Digest`；不得复用 session-grant introspection bearer。

旧的 `POST /_coauth/self/agents/{id}/accountability-grant` 产品私有入口没有
canonical operation，也没有现行调用者，现已移除。Accountability 事实继续通过
规范登记的 Event 与 Station projection 表达。
