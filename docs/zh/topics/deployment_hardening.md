# 部署强化（Deployment Hardening）

本章讨论影响 coauth 审计可追溯性与出站网络策略严格程度的部署级决策。

## 管理审计行的签名

管理审计行使用 transcript schema
`org.arkret.coauth.audit.admin_operation.v1`。分离签名绑定仓储行 id、
`created_at`、`admin_user_id`、operation、资源类型、资源 id、details、
IP 地址、User-Agent 与 schema 版本。管理审计的读取 / 导出接口返回
`signature_status`：

- `verified` —— 该行可用当前服务 JWKS 验证通过。
- `unsigned` —— 该行是在灰度期 fail-open 模式下写入的。
- `invalid` —— 签名存在但已与行内容不匹配。
- `key_unavailable` —— 该行引用的服务 DID/kid 本进程无法验证。

`ak.session.grant` 由 kid 为 `coauth-session-grant-v1` 的密钥签名，同样按名字
选取。密钥集中没有该 kid 时不签发任何 grant：若改按算法顺序选取，新增或重排
其它密钥就会悄悄改变签发密钥与 grant 头部的 kid。上线前必须配置该密钥；轮换时
把退役公钥保留在 JWKS 中直到相关 grant 全部过期。

审计行由 durable runtime key bundle 中 kid 为 `coauth-audit-signing-v1` 的 Ed25519 密钥
签名。它按名字选取，不按算法：密钥集按算法查找返回的是**最后一个**匹配项，
按算法选会让审计签名者随任何一把 Ed25519 密钥的增删或重排而悄悄变化，
而每一行签名里记录的 kid 也随之改变。没有配置这把密钥时，行按 fail-open
规则写为 `unsigned`（`fail_closed: true` 时拒绝写入）。

签名密钥灰度期间保持 `arkret.audit_signature_fail_closed: false`。对生产
受监管业务，先发布服务 JWKS，确认审计流对新行报告 `verified`，再设为
`arkret.audit_signature_fail_closed: true`，使 coauth 在无法产出已签名审计行
时对敏感管理变更 fail closed。

密钥轮换期间，把已退役的公钥保留在部署 JWKS 中直到审计保留期结束，否则历史行
会从 `verified` 变成 `key_unavailable`。把 `invalid` 当作篡改或损坏信号处理：
保留数据库快照，将导出的行 JSON 与运营方权威记录比对，不要为了消除告警而删除
该行。导出应携带与管理审计流相同的 `signature_status` 字段，便于离线审计者区分
“未签名”与“验签失败”。

## 出站 HTTP 与 SSRF 护栏

coauth 生产代码必须使用共享的 `outbound_http::reqwest_client` 工厂。该工厂安装：

- rustls 平台证书校验；
- 禁止重定向、不继承代理；
- 拒绝 localhost、私有网段、link-local、组播、文档保留段与云元数据目标的
  DNS 解析器；
- 请求与连接超时；
- OpenTelemetry 客户端 span 与指标。

新增出站 HTTP 调用点应使用该工厂，以保证 SSRF、超时、TLS 与遥测策略一致。

OIDC discovery 与 JWKS 拉取走同一共享客户端，并拒绝超过 1 MiB 的响应体，避免恶意
或配置错误的上游把元数据刷新变成无界内存消耗。

所有构建一律拒绝私有网络出站。共享客户端刻意不提供进程级私网逃生舱——仅凭主机名
的允许列表无法表达受控网络例外所需的用途、服务身份、CIDR、端口、有效期与审计要求。

上游 OIDC、已配置的 `identity_registry` resolver、soland webvh 注册与 policy
裁决调用应优先使用公网可路由的
服务端点。若部署确实需要私有服务 URL，请通过专用出站代理路由，由代理策略绑定目标
服务身份、信任域、CIDR、端口、有效期与审计记录。
