# 部署强化（Deployment Hardening）

本章讨论影响 coauth 对可问责性（accountability）和撤销链路严格程度的
部署级开关。最重要的单个开关是 `cx.profile.accountable_to.strict_reject.v1`
profile，它将默认的“软警告”姿态切换为“硬拒绝”。

## `accountable_to.strict_reject` profile

默认情况下，coauth 运行在**宽松**可问责性姿态：
`accountable_to` 链上陈旧或未知的环节只会记录结构化告警，不会阻断
session grant 签发。这是多租户部署下的安全默认值——某些对端尚未升级
其可问责性形状，硬拒绝会直接造成用户可见的故障级联。

严格拒绝（strict-reject）profile 反转这一姿态：链上任何未知、陈旧或不
匹配的环节都会在 session grant 签发时产生硬拒绝。

### 何时声明

满足下列**任一**条件时声明 strict-reject：

1. **受监管业务**。审计要求可问责性链路异常必须导致硬失败（而不是软日
   志）。
2. **审计日志被消费**。下游审计或合规系统在读可问责性流，静默丢弃的
   claim 会造成审计空缺。
3. **可问责性漂移定位**。在排查为何 claim 总是过期到达——开严格拒绝把
   噪声转为运维大盘已经在告警的硬信号。
4. **高保证企业租户**。租户 SLA 明确要求严格执行。

下列情况**不要**声明 strict-reject：

- 你没有审计过去 24 小时的可问责性 claim，对“陈旧 vs 新鲜”的基线没有
  概念。
- 你依赖的联邦对端尚未升级。
- 你在发布窗口里——开关产生的临时 4xx 尖峰看起来很像回归 bug。

### 预期后果

开启 profile 之后：

1. **4xx 拒绝量尖峰**。原来记日志的陈旧 claim 现在直接拒绝。监控 4xx
   比率的告警 **必须** 提前通知，最好对 flip 窗口做静音。
2. **联邦对端被拒**。来自未升级形状的对端联邦事件将开始失败。flip 前
   要与联邦伙伴书面协调，明确切换时点。
3. **上游到 soland 的流量上升**。Strict-reject 通常会把撤销新鲜度窗口
   固定到 `<= 30s`，这意味着 coauth 更频繁地刷新镜像状态。预计针对
   agent-state 与 accountability-grant 接口的上游 RPC 速率会到基线的
   约 2 倍。
4. **agent 运行时路由启用后的硬拒绝放大**。`agent_paused`、
   `agent_deactivated`、`accountability_grant_missing` 从“记日志+拒绝”
   升级为“记日志+拒绝+告警”——在暴露暂缓的 agent runtime 接口前，确保
   运维准备就绪。

### Flip 前检查清单

1. 取过去 24 小时的可问责性 claim 到达量，分类为陈旧 vs 新鲜。开关之前
   陈旧比应 < 2%；如果 > 5%，flip 会产生过多噪声而无法被有效审计。
2. 决定切换时点；提前以书面形式通知联邦伙伴。
3. 提前静音覆盖 flip 时点前后 60 分钟的 4xx 比率告警。
4. 由 realm 运营者发出 `cx.realm.profile.update`，将
   strict-reject profile 加入 realm 已声明的 profile 集合。
5. 持续观察 30 分钟：
   - `coauth_accountable_to_reject_total{profile="strict"}` —— 从 0 起跳
     后，应在“陈旧基线 + 20%”范围内趋稳。
   - `coauth_session_grant_failure_total{reason="agent_paused" | "agent_deactivated" | "accountability_grant_missing"}` —— 仅在暂缓的 agent runtime
     接口接线后适用；届时应保持在 flip 前的基线。
6. 若拒绝数超阈值：回滚（关掉 profile），对最吵的对端立 bug，等待对端
   升级后再次 flip。

### 审计日志预期

Strict-reject 是一项可审计的姿态变化。flip-on / flip-off 都 **必须** 出
现在审计日志中，事件 kind 为
`profile.accountable_to.strict_reject.flip`。该审计行携带：

- `realm_id`
- `direction`（`on` 或 `off`）
- 操作者的 `actor_id`
- `timestamp`
- realm profile 集合的 `prior_state_digest` 与 `new_state_digest`
- `justification`（操作者填写的自由文本）

在 strict-reject 生效期间，每一次拒绝还会产生一行
`accountable_to.strict_reject.reject` 审计行：

- `realm_id`
- `chain_anchor`（被拒绝的链锚 Principal）
- `reason`（`stale` / `unknown` / `mismatch` / `chain_break` 其一）
- `requested_operation`（例如 `cx.account.issue_session_grant`）
- `timestamp`

这些行会被合规管线消费。审计保留期内（默认 90 天，以租户 SLA 为准）
**不要**清理。

### 回滚

回滚 strict-reject：

1. 运营者再发一次 `cx.realm.profile.update`，将
   `cx.profile.accountable_to.strict_reject.v1` 从 realm 已声明的
   profile 集合中移除。
2. 已审计的在途拒绝保持已审计状态；不再触发新的拒绝判断。
3. coauth 在下一次镜像刷新内（`revocation_freshness_window` 内）恢复默
   认宽松姿态。
4. 写入一行 `direction = off` 的
   `profile.accountable_to.strict_reject.flip` 审计行。

开关粒度是 **realm 级**，不是部署全局级。同一个 coauth 部署可以同时为
某些 realm 启用 strict-reject，为另一些 realm 维持默认姿态。
