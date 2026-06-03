# coauth 审查报告 04：结构建议调整

> 被审项目：`D:/Works/contrix-dev/coauth`（约 33.6 万行 / 1143 文件，Rust workspace，18 个 crate）。
> 性质：Contrix Auth / Account Server（OIDC/OAuth IdP + 账号生命周期 + admin API），源出 matrix-authentication-service（MAS）派生（多文件保留 `Copyright … The Matrix.org Foundation` 头）。
> 本报告仅覆盖「工程结构」维度。

## 审查范围

实际通读 / 检索的路径（均相对 `coauth/`）：

- workspace 布局与 crate 划分：`Cargo.toml`（root workspace）、各 `crates/*/Cargo.toml`。
- crate 规模统计（`find … *.rs | wc -l`，排除 `target/`）：`backend` 92404 行、`data` 40167、`frontend` 8816、`config` 6980、`oauth-types` 6493、`jose` 5676 …
- backend 顶层布局：`crates/backend/src/`（`handlers/`、`services/`、`server.rs`、`error.rs`、`app_state.rs`、`storage.rs`、`sync.rs` …）。
- backend handlers 子树：`crates/backend/src/handlers/`（`account/`、`admin/`、`oauth/`、`upstream_oauth/`、`flow/`、`views/`、`contrix.rs`、`passwords.rs` …）。
- 最大文件清单（`wc -l | sort`）：`handlers/contrix.rs` 4404、`handlers/admin/v1/user_registration_tokens.rs` 2672、`handlers/account/service/registration.rs` 2488、`handlers/account/auth/oidc_bridge.rs` 2113 …
- data crate 结构：`crates/data/src/`（域类型）、`crates/data/src/storage/`（repository trait）、`crates/data/src/pg/`（Postgres 实现）。
- crate 间依赖关系（逐 `Cargo.toml` 抽取 `coauth-*`/`oauth-types` 依赖边）。
- 错误类型组织：`crates/backend/src/error.rs`、`crates/backend/src/handlers/common.rs:148`，以及 backend 内 129 个 `enum *Error`、9+ 个同名 `RouteError`。
- `crates/backend/src/handlers/contrix.rs` 全文 item 大纲（`grep '^(pub )?…fn|struct|enum|impl'`）。

复验命令：
```
find crates -name '*.rs' -not -path '*/target/*' | xargs wc -l | sort -rn | head -35
grep -rn 'enum RouteError\|struct RouteError' crates/backend/src
grep -nE '^(pub )?(async )?fn |^pub struct |^pub enum |^impl ' crates/backend/src/handlers/contrix.rs
for d in crates/*/; do grep -oE 'coauth-[a-z-]+|oauth-types' "$d/Cargo.toml"; done
```

未覆盖：`frontend`（leptos SPA，8816 行，仅结构层面扫了规模未逐文件读）、`messaging`/`templates`/`tasks` 内部模块切分仅抽样、`backend/src/handlers/views/` 与 `flow/` 子树未逐文件审。优先覆盖了 backend handlers/services、data 分层、crate 依赖边与错误类型组织。

## 结论摘要

整体工程分层是健康的：18 个 crate **无循环依赖**，依赖方向单向收敛到 `backend`/`cli`；`data` crate 采用 trait（`storage/`）与 Postgres 实现（`pg/`）分离的经典 repository pattern，可测试性好。主要结构问题集中在 **backend crate 的单体化**：92k 行全部塞进一个 crate，存在超大文件（`contrix.rs` 4404 行混杂 7+ 种职责）、域逻辑被错误地放进 `handlers/`（如 `passwords.rs` 是纯密码学域逻辑、零 handler）、错误类型碎片化（9 个同名 `RouteError`、129 个 `*Error`）。本维度共保留 **5** 条问题，最高 **P2**。

---

## 问题 1：`handlers/contrix.rs` 单文件混杂 7+ 种不相关职责（4404 行）

- **严重级别**：P2
- **证据**：
  - `crates/backend/src/handlers/contrix.rs`：全文 4404 行，是仓库最大单文件。其 item 大纲显示同一文件内承载了互不相关的多个领域：
    - Session Grant 签发/校验/吊销/内省：`SessionGrantError`（:36）、`SessionGrantMaterial`（:269）、`SessionGrantPayload`（:382）、`SessionGrantIntrospection*`（:721–:784）、`require_session_grant_caller`（:113）。
    - DID Document 服务：`DidDocument`（:295）、`DidDocumentMetadata`（:337）、`VerificationMethod`（:358）、`local_user_did_document_if_owned`（:1786）、`did_document_as_of_query`（:1773）。
    - Handle Claim 签发：`HandleClaimPayload`（:955）、`HandleClaimMaterial`（:984）、`HandleClaimKind`（:1014）、`HandleClaimDigestInput`（:1165）。
    - Service / Identity / Directory describe & resolve：`ServiceDescribeResponse`（:542）、`service_describe_response`（:1424）、`server_describe`（:2058）、`identity_describe`（:2115）、`identity_resolve`（:2137）、`ResolveHandleResponse`（:674）。
    - 多套描述符 DTO：`PrincipalServerDescriptor`（:455）、`IdentityRegistryDescriptor`（:463）、`ServiceBoundaryDescriptor`（:478）、`StandardErrorEnvelopeDescriptor`（:486）…
    - 签名密钥选择工具：`preferred_signing_key`（:1990）、`preferred_public_signing_key`（:2016）。
    - trust_domain 推导：`trust_domain_for`（:1183）、`derived_trust_domain_scope`（:1192）。
- **影响**：单文件承载 session-grant / DID / handle-claim / service-describe / identity-resolve 五条独立协议子表面，任何一处改动都要打开 4404 行文件，code review diff 噪声大；多人并行修改极易产生 merge 冲突；编译单元过大拖慢增量编译；新成员难以定位职责边界。
- **建议**：按职责拆为 `handlers/contrix/` 子模块目录：`session_grant.rs`、`did_document.rs`、`handle_claim.rs`、`service_describe.rs`（含各 descriptor DTO）、`identity_resolve.rs`、`keys.rs`（`preferred_signing_key` 系列）、`trust_domain.rs`。共享的 `ContrixRouteError`（:63）放 `handlers/contrix/error.rs` 或上提到 `handlers/common.rs`。
- **复验结论**：已重新打开 `contrix.rs` 上述各行号确认 item 名称与起始行属实；4404 行经 `wc -l` 复核。条目成立。

---

## 问题 2：纯域逻辑 `passwords.rs` 误置于 `handlers/`（语义错位，且应上移为独立 crate/模块）

- **严重级别**：P2
- **证据**：
  - `crates/backend/src/handlers/passwords.rs`：含 `PasswordVerificationResult`、`Algorithm`（Bcrypt/Argon2id/Pbkdf2，:377/:390/:406）、`hash`/`verify` 逻辑、zxcvbn 强度校验，但 `grep -cE '#\[handler\]|#\[endpoint'` 结果为 **0** —— 该文件不含任何 HTTP handler，是纯密码哈希域逻辑（直接 `use argon2::…PasswordHasher`、`use pbkdf2::Pbkdf2`、`use zxcvbn::zxcvbn`）。
  - 对比：`handlers/` 目录的语义约定是 HTTP 入口（`account/`、`oauth/`、`admin/` 等子树都是 endpoint）。
- **影响**：目录布局与职责不匹配——读者看到 `handlers/passwords.rs` 会误以为是「密码相关的 HTTP 端点」，实际是密码学原语；密码哈希这种安全敏感、可独立测试、可被 `cli`/`tasks` 复用的逻辑被锁死在 backend 的 handlers 命名空间下，无法被其他 crate 直接依赖。
- **建议**：把密码哈希逻辑移出 `handlers/`。最小改动：移到 `crates/backend/src/services/passwords.rs`（与 `services/dpop.rs`、`services/policy_signer.rs` 同级，services 是 backend 内的域逻辑层）。更彻底：抽成独立 `crates/passwords/`（依赖 argon2/bcrypt/pbkdf2/zxcvbn），供 backend 与 cli 复用——MAS 上游正是 `mas-data-model` + 独立密码模块的形态。
- **复验结论**：已重开 `passwords.rs` 头部确认无 handler 宏、纯密码学 import；`grep -c` 复核 handler 数为 0。条目成立。

---

## 问题 3：`RouteError` 类型名重复 9+ 次、backend 内 129 个 `*Error`，错误类型组织碎片化

- **严重级别**：P3
- **证据**：
  - `grep -rn 'enum RouteError'` 在 backend 命中至少 9 处同名定义：`handlers/common.rs:148`、`handlers/oauth/authorization/consent.rs:18`、`handlers/oauth/authorization/mod.rs:27`、`handlers/oauth/device/authorize.rs:20`、`handlers/oauth/introspection.rs:35`、`handlers/oauth/registration.rs:41`、`handlers/oauth/revoke.rs:22`、`handlers/oauth/token.rs:42`、`handlers/oauth/userinfo.rs:48`、`handlers/upstream_oauth/authorize.rs:17`。
  - backend 内 `grep -rn 'enum .*Error' | wc -l` = **129** 个错误枚举。
  - 顶层错误聚合在 `crates/backend/src/error.rs`（`AppError` + `BoxError`），与各 handler 的局部 `RouteError`（`handlers/common.rs:148`）并存两套体系。
- **影响**：同名 `RouteError` 散落 9+ 模块，跨模块引用必须用路径别名（`error.rs:14` 已出现 `RouteError as RestRouteError` 的别名修补），增加心智负担；新增端点时复制粘贴 `RouteError` 模板易产生不一致的 status/正文映射；129 个错误枚举缺乏统一的 wire error-code 归一层（对照 spec `error-code-registry.json` ~230 条 reason_code，难以保证 coauth 输出与 registry 对齐）。
- **建议**：
  1. 每个 oauth 子模块的 `RouteError` 重命名为领域专属名（`TokenRouteError`/`ConsentRouteError`…），消除别名修补。
  2. 引入一个集中的 `ErrorCode`/`ReasonCode` 枚举（对齐 spec `error-code-registry.json`），各局部 `*Error` 通过 `impl From` 收敛到统一 wire 表示，避免 129 处各自决定 HTTP status 与正文。
- **复验结论**：已逐一打开上述 9 个 `RouteError` 行号确认为独立同名定义；`error.rs:14` 的 `RestRouteError` 别名属实；129 计数来自 `grep | wc -l`。条目成立。

---

## 问题 4：backend 是 92k 行单体 crate，admin/account 子表面应进一步切分

- **严重级别**：P3
- **证据**：
  - `crates/backend/` 单 crate 92404 行，占全 workspace（约 184k 行 src，不含 lock）的一半。
  - 内部已有多个超大文件并存于同一编译单元：`handlers/admin/v1/user_registration_tokens.rs` 2672、`handlers/account/service/registration.rs` 2488、`handlers/account/auth/oidc_bridge.rs` 2113、`handlers/oauth/token_service.rs` 1697、`handlers/upstream_oauth/link.rs` 1683、`handlers/admin/v1/upstream_oauth_links.rs` 1667、`server.rs` 1458、`handlers/account/register.rs` 1470。
  - `admin/` 子树合计 20626 行（`find handlers/admin -name '*.rs' | wc -l`）。
- **影响**：单一 92k 行 crate 是增量编译瓶颈（任何改动触发整 crate 重编 + 重跑 clippy）；CI 上无法对 admin/account/oauth 子表面做独立的编译/测试隔离；feature flag 粒度受限。
- **建议**：将 backend 内边界清晰的子表面下沉为独立 crate（保持 handler 薄、域逻辑厚）：`coauth-admin-api`（`handlers/admin/v1/*`，已有 `coauth-admin-types` 作为类型层可对接）、`coauth-oauth-flows`（`handlers/oauth/*` + `handlers/upstream_oauth/*`）。短期内若不拆 crate，至少把 2000+ 行的 `user_registration_tokens.rs`/`registration.rs`/`oidc_bridge.rs` 按「路由 vs 域逻辑 vs DTO」三段拆文件。
- **复验结论**：已用 `wc -l` 复核 backend 总行数与各超大文件行数；admin 子树 20626 行经 `find|xargs wc -l` 复核。条目成立。

---

## 问题 5（正向记录 + 1 处可见性/职责小问题）：分层总体健康，但 `templates` crate 反向依赖 `data`/`policy`

- **严重级别**：P3
- **证据**：
  - 逐 `Cargo.toml` 抽取依赖边，确认 **无循环依赖**，方向单向收敛：`iana`←`jose`←`keystore`/`oauth-types`/`config`，`data`←`policy`/`templates`/`tasks`，最终汇入 `backend`←`cli`。`data` crate 的 `storage/`（trait，如 `storage/account.rs:42 pub trait AccountRepository`）与 `pg/`（Postgres 实现）分层清晰——此为应保留的良好结构。
  - 但 `crates/templates/Cargo.toml` 依赖 `coauth-data`、`coauth-policy`、`coauth-i18n`、`oauth-types`（`templates/src/lib.rs` 头 `use coauth_data::UrlBuilder; use coauth_i18n::Translator;`）。一个「模板渲染引擎」（自述 "wraps minijinja"）反向耦合了数据访问层与策略层。
- **影响**：模板 crate 本应是叶子层（只依赖渲染所需的轻量类型），却拉入 `data`（含 Postgres repository 体系）与 `policy`（含 Cedar），抬高了 templates 的编译成本与耦合面，削弱了「模板可独立复用/测试」的初衷。
- **建议**：审查 templates 对 `coauth-data`/`coauth-policy` 的实际使用面。若仅用到 `UrlBuilder` 这类轻量类型，将其下沉到一个无 DB 依赖的 `coauth-core-types`/`config` 层，使 templates 只依赖纯类型，不依赖 repository/policy 实现。
- **复验结论**：已重开 `crates/templates/Cargo.toml` 与 `templates/src/lib.rs` 头确认依赖 `coauth-data`/`coauth-policy`/`coauth-i18n`；无循环依赖结论来自全 crate 依赖边抽取。条目成立。

---

## 附：本报告确认为「非问题/良好实践」（不计入问题数）

- **无循环依赖**：18 crate 依赖图单向，无环。
- **data crate 的 trait/impl 分层**（`storage/` 定义 `*Repository` trait，`pg/` 提供 Postgres 实现）是教科书式 repository pattern，应保留。
- **canonical JSON 未重复造轮**：详见报告 07，coauth 各处统一调 `contrix_core::canonical`。
