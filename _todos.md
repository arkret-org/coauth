# coauth Active TODO

> 更新日期: 2026-04-29
> 范围: 组织部署 Principal Server 时使用的 Auth / Account Server，提供 OIDC/SSO、账号生命周期、DID 绑定、设备/会话、claim/attestation、权限与审计管理。

## 0. 当前边界

- 当前代码主体仍来自 Pasion / Matrix delegated auth 语境，`_tasks.md` 保留为 legacy 维护清单。
- Contrix 语境下，`coauth` 不应成为 DID Registry；DID document、`did:uuid`、key-log 和 registry receipt 属于 `starid`。
- `coauth` 的职责是证明“谁登录了哪个账号/设备”，并向 Principal Server / 管理界面提供可审计的 session grant、claim、账号策略和 admin API。
- 现有 OAuth2/OIDC、上游 IdP、注册/恢复 workflow、通知、Cedar/OPA policy、admin API 是可复用基础，但必须移除 Matrix/Palpo/Pasion 专有假设。

## P0: Contrix 产品边界和命名收敛

目标: 文档、配置、API 和代码语义从 Matrix/Pasion 迁移到 Contrix/coauth。

- [x] README / docs 重写:
  - [x] 项目定位改为 Contrix Auth / Account Server。
  - [x] 移除 Palpo / Matrix 作为主路径的描述。
  - [x] 保留 Matrix compatibility 时标记为 legacy adapter。
  - [x] 补 Principal Server、starid、sodmin、chask 的集成说明。
- [ ] 配置模型收敛:
  - [ ] `matrix` 配置段移入 compatibility profile。
  - [x] 新增 `contrix.principal_servers`。
  - [x] 新增 `contrix.identity_registry` / starid resolver 配置。
  - [x] 新增 service DID、issuer DID、admin audience。
- [ ] scope 命名收敛:
  - [x] `urn:coauth:admin` 保留为 coauth 管理权限。
  - [x] 新增 `urn:contrix:client:*`。
  - [x] 新增 `urn:contrix:principal-server:*`。
  - [x] 新增 `urn:contrix:admin:*`。
  - [ ] Matrix scopes 只在 compatibility adapter 中出现。
- [ ] 代码命名分层:
  - [x] 新增 Contrix module / route group。
  - [x] Pasion/Matrix 特有 handler 不得被 Contrix 默认路由引用。
  - [ ] i18n 文案同步替换。

并行性: docs/config/scope/i18n 可并行，但 scope registry 必须先冻结，避免 sodmin 与 chask 重复改动。

## P0: Principal、账号与会话模型

目标: 登录服务输出 Contrix 可验证的账号/设备/session 绑定，而不是仅输出 OAuth access token。

- [ ] 数据模型:
  - [ ] Account 与 principal DID 绑定。
  - [ ] 一个账号支持多个 DID binding，区分 primary、recovery、pairwise/private。
  - [ ] 设备 DID / device_id 与登录 session 绑定。
  - [x] session grant 记录 issuer、subject DID、device_id、audience、scope、expires_at、revoked_at。
  - [ ] refresh token 只保存 hash，绑定 device/session/audience。
- [ ] 登录输出:
  - [ ] OAuth/OIDC token 携带 Contrix audience。
  - [x] token claims 包含 principal DID、device_id、session id。
  - [ ] 高风险 scope 需要 MFA / passkey / policy proof。
  - [ ] token 不进入 query string。
- [ ] 账号生命周期:
  - [ ] locked: 禁止新写入，允许有限只读和恢复。
  - [ ] disabled: 禁止登录和 token refresh。
  - [ ] erased: admin/search/profile 不泄露个人信息。
  - [ ] session revoke cascade 到 Principal Server。
- [ ] 设备生命周期:
  - [ ] 设备登记。
  - [ ] 设备重命名。
  - [ ] 设备吊销。
  - [ ] 设备风险等级和 MFA 状态 claim。

## P0: DID 绑定、恢复和 Claim / Attestation

目标: coauth 负责账号到 DID 的绑定证明与组织 claim，不直接篡改 DID Registry。

- [ ] starid 集成:
  - [ ] 解析 DID document。
  - [ ] 校验 DID control proof。
  - [ ] 提交 DID binding 前检查 key-log current control key。
  - [ ] 私有 / pairwise DID resolve 需要 proof。
- [ ] DID binding workflow:
  - [ ] attach existing DID。
  - [ ] create managed DID bootstrap request。
  - [ ] rotate/recover DID binding。
  - [ ] unlink DID with audit trail。
  - [ ] break-glass recovery 审批。
- [ ] Handle / email / org claim:
  - [ ] verified handle claim。
  - [ ] verified email domain claim。
  - [ ] org membership claim。
  - [ ] org role claim。
  - [ ] employment / contractor / guest status。
  - [ ] guardian / controller relationship。
- [ ] Progressive disclosure:
  - [ ] presentation request endpoint。
  - [ ] disclosure policy。
  - [ ] SD-JWT / BBS VC adapter boundary。
  - [ ] claim revocation status list。
  - [ ] fail-closed when required revocation status is unavailable。

## P0: Contrix OIDC / OAuth2 Contract

- [x] OIDC discovery advertises Contrix-specific claims and scopes。
- [ ] Dynamic client registration supports:
  - [ ] `chask` public/native client。
  - [ ] `sodmin` admin dashboard。
  - [ ] `soland` trusted Principal Server。
  - [ ] internal service client for federation/admin automation。
- [ ] Device code grant supports CLI/admin workflows。
- [ ] Passkey/WebAuthn:
  - [ ] registration ceremony。
  - [ ] authentication ceremony。
  - [ ] recovery interaction。
  - [ ] step-up for high-risk admin scopes。
- [ ] OIDC upstream mapping:
  - [ ] external IdP subject maps to local account。
  - [ ] external IdP claim maps to Contrix claim only through trusted issuer rules。
  - [ ] upstream logout/session revocation handling。

## P0: Admin API for sodmin

目标: `sodmin` 不依赖 legacy Pasion admin API shape。

- [ ] OpenAPI:
  - [ ] `/api/admin/v1/openapi.yaml`。
  - [ ] `/.well-known/contrix/openapi.yaml`。
  - [ ] ErrorEnvelope 与 Contrix API convention 对齐。
- [ ] Account admin:
  - [ ] list/search accounts。
  - [ ] account detail。
  - [ ] lock/disable/erase。
  - [ ] reset recovery workflow。
  - [ ] list account DIDs。
  - [ ] add/remove DID binding。
- [ ] Session/device admin:
  - [ ] list sessions。
  - [ ] revoke session。
  - [x] list session grants。
  - [x] revoke session grant。
  - [ ] list devices。
  - [ ] revoke device。
  - [ ] view token/audience/scope metadata without secrets。
- [ ] Claim/policy admin:
  - [ ] issue/revoke claim。
  - [ ] list claim status。
  - [ ] policy check dry-run。
  - [ ] signed policy decision audit。
- [ ] OAuth/admin integrations:
  - [ ] upstream providers。
  - [ ] OAuth2 clients。
  - [ ] registration tokens。
  - [ ] notification templates/channels。
  - [ ] connector health。
- [ ] Audit:
  - [ ] every admin mutation writes actor, device, target, reason, request id。
  - [ ] high-risk action requires reason and optional approval proof。

## P1: Policy and Capability Integration

- [ ] Map coauth policy decisions to Contrix capability semantics:
  - [ ] policy can deny/quarantine/require_review。
  - [ ] policy cannot grant missing capability。
  - [ ] signed policy decision includes policy id, version, subject, action, resource, frontier。
- [ ] Cedar/OPA mapping:
  - [ ] principal DID。
  - [ ] device id。
  - [ ] organization role claim。
  - [ ] risk/MFA claim。
  - [ ] admin scope。
- [ ] Approval workflows:
  - [ ] proposal mode。
  - [ ] two-person approval。
  - [ ] guardian/controller approval。
  - [ ] break-glass with audit expiry。

## P1: Notification and Verification Runtime

- [ ] Email/SMS verification templates renamed to Contrix/coauth。
- [ ] Notification dispatch never leaks recovery or token secrets in logs。
- [ ] Rate limits:
  - [ ] login。
  - [ ] recovery。
  - [ ] MFA。
  - [ ] DID binding。
  - [ ] admin mutation。
- [ ] Abuse controls:
  - [ ] CAPTCHA policy hook。
  - [ ] suspicious session risk claim。
  - [ ] account enumeration resistance。

## P1: Migration and Compatibility

- [ ] Legacy Matrix compatibility adapter is optional and disabled by default for new Contrix deployments。
- [ ] Migration tool:
  - [ ] Pasion users -> coauth accounts。
  - [ ] Matrix localpart -> handle claim candidate。
  - [ ] existing OAuth clients -> Contrix client registry。
  - [ ] admin scopes -> Contrix admin scopes。
- [ ] Docs list which legacy routes remain supported and which are removed。

## P1: Test and Release Gates

- [ ] Unit tests for session grant, DID binding, claim issuance and revocation。
  - [x] session grant signing unit test。
- [ ] HTTP contract tests for all admin endpoints。
- [ ] OIDC conformance smoke against generated discovery/JWKS/token endpoints。
- [ ] Integration stack with `soland` + `starid` + `sodmin`。
- [ ] Security review checklist:
  - [ ] token storage。
  - [ ] WebAuthn ceremony。
  - [ ] recovery flow。
  - [ ] admin audit。
  - [ ] log redaction。

## 本轮验证记录

- [x] 2026-04-29: `cargo fmt --check`。
- [x] 2026-04-29: `cargo check -p coauth-data --message-format short`。
- [x] 2026-04-29: `cargo check -p coauth-backend --message-format short`。
- [x] 2026-04-29: `cargo test -p coauth-backend session_grant --message-format short`。
- [x] 2026-04-29: `cargo test -p coauth-data session_grant --message-format short`。

## Definition of Done

- [ ] New Contrix functionality is documented in README and OpenAPI。
- [ ] Production path does not depend on Matrix/Palpo/Pasion naming or scopes。
- [ ] Every session/token is bound to principal DID, device, audience and expiry。
- [ ] Every DID/claim operation has proof verification and audit trail。
- [ ] `sodmin` can manage coauth through stable Contrix admin APIs。
