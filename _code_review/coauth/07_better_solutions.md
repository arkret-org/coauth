# coauth 审查报告 07：存在更优方案 / 依赖库 / 技术未采用

> 被审项目：`D:/Works/contrix-dev/coauth`（Contrix Auth/Account Server，matrix-authentication-service 派生）。
> 本报告聚焦「是否存在更成熟/更安全/更高效的方案、依赖库或语言特性而未采用」。

## 审查范围

实际通读 / 检索的路径（相对 `coauth/`）：

- 加密 / JOSE 自实现：`crates/jose/src/`（`lib.rs`、`jwa/`、`jwk/`、`jwt/signed/`、`claims.rs`、`base64.rs`、`constraints.rs`）、`crates/jose/Cargo.toml`。
- OAuth/OIDC 类型自实现：`crates/oauth-types/src/`（`oidc.rs` 1904 行、`requests.rs`、`pkce.rs`、`scope.rs`、`webfinger.rs`）。
- TOTP 自实现：`crates/backend/src/totp.rs`。
- canonical-JSON 使用面：`crates/backend/src/handlers/contrix.rs:1662`、`crates/backend/src/handlers/account/agents.rs:370`、`crates/backend/src/services/soland_webvh.rs:340`、`crates/backend/src/services/policy_signer.rs:127`（全部走 `contrix_core::canonical`）。
- 签名密钥选择逻辑重复：`crates/backend/src/handlers/contrix.rs:1990 preferred_signing_key` vs `crates/backend/src/services/policy_signer.rs:169 preferred_service_signing_key`。
- workspace 依赖清单：`Cargo.toml`（crypto/json 段）。
- SDK 既有能力：`D:/Works/contrix-dev/contrix-rust-sdk/crates/{core,contracts}`（经 spec_digest §5 锚点），以及 `spec_digest.md` 全文。

复验命令：
```
grep -rniE 'mas-?jose|forked|adapted from' crates/jose
grep -rn 'fn canonical\|sort_keys\|contrix_core::canonical' crates/*/src
sed -n '1990,2014p' crates/backend/src/handlers/contrix.rs
sed -n '169,200p' crates/backend/src/services/policy_signer.rs
head -40 crates/backend/src/totp.rs
```

未覆盖：`jose` 各 JWA 算法实现的逐行密码学正确性（属安全维度，本报告只看「是否该自实现」）、`frontend` 的 leptos 用法。优先覆盖了与「重复造轮 / 库选型 / SDK 复用」直接相关的 crate。

## 结论摘要

coauth 在 **canonical-JSON 这一最易踩的点上做得正确**——全仓统一复用 SDK 的 `contrix_core::canonical`，未手写。最大的「自实现」是 `jose` 与 `oauth-types` 两个 crate，但这是从 matrix-authentication-service 派生的既定架构选择（成熟、经审计、贴合 IdP 需求），不应轻易替换，仅记录其维护成本与可收敛点。真正可立即改进的是：**两处签名密钥选择逻辑各写一遍**（应合并）、以及对 SDK 既有 wire 类型的复用核查。本报告保留 **4** 条建议，最高 **P2**。

---

## 问题 1：`preferred_signing_key` 与 `preferred_service_signing_key` 是同一段密钥优选逻辑的两份拷贝

- **严重级别**：P2
- **证据**：
  - `crates/backend/src/handlers/contrix.rs:1990-2014` `fn preferred_signing_key`：按固定优先序 `[EdDsa, Es512, Es384, Es256, Rs512, Rs384, Rs256, Ps512, Ps384, Ps256]` 遍历，`find_map` 取第一个 keystore 中可用的签名密钥。
  - `crates/backend/src/services/policy_signer.rs:169-179` `fn preferred_service_signing_key`：完全相同的算法优先序数组与 `find_map` 逻辑；其文档注释（:161-168）明确写道「Mirrors `handlers::contrix::preferred_signing_key` so the policy decision signer uses the *same* key …」——即作者已知是镜像复制。
- **影响**：service-issued artefact（session-grant JWT、handle-claim proof、policy decision 签名）依赖「同一把 service key」这一不变量。现以两份独立常量数组维持该不变量，任一处增删算法或调整优先序，另一处会静默漂移，导致两类签名落到不同 key/alg —— 验证方可能因 kid 不一致而拒绝。这是典型的「靠注释维持的隐式契约」反模式，应由类型/单一函数强制。
- **建议**：把优先序与选择逻辑提为 keystore 层（`coauth-keystore`）的一个公开方法，例如 `Keystore::preferred_service_signing_key() -> Option<(JsonWebSignatureAlg, &JsonWebKey<PrivateKey>)>`，两个调用点共用。优先序数组作为 keystore 内的单一 `const`。这样不变量由编译期单点保证，而非两份注释。
- **复验结论**：已并排打开两处函数体，确认算法数组、`find_map` 结构、注释中的 "Mirrors" 自述均属实。条目成立。

---

## 问题 2：手写 `jose` / `oauth-types` crate —— 记录为「既定派生选择」，给出收敛建议（非要求替换）

- **严重级别**：P3
- **证据**：
  - `crates/jose/src/`：完整手写 JOSE 栈——`jwa/{asymmetric,hmac,signature,symmetric}.rs`、`jwk/{public,private}_parameters.rs`、`jwt/signed/{sign,verify,decode}.rs`、`base64.rs`、`constraints.rs`。`jose/Cargo.toml` 直接依赖底层原语（`ecdsa`、`ed25519-dalek`、`rsa`、`k256/p256/p384/p521`、`hmac`、`sha2`、`sec1`）。
  - `crates/oauth-types/src/oidc.rs` 1904 行 + `requests.rs` 1045 行：手写 OAuth/OIDC discovery、provider metadata、request/response 体。
  - 多文件保留 `Copyright 2022-2024 The Matrix.org Foundation C.I.C.`（如 `handlers/passwords.rs:2`）——表明 `jose`/`oauth-types` 实为 `mas-jose`/`oauth2-types`（MAS 生态）派生，而非凭空手写。
- **影响**：生态中已有 `josekit`、`jsonwebtoken`、`openidconnect` 等成熟 crate。但 MAS 派生的 `mas-jose` 是为「同时作 IdP 签发方与 upstream 验证方」设计的，类型状态化（`Jwt<T>` 已签/未签区分、`Constrainable` 约束）比 `jsonwebtoken` 更贴合本项目，且已随 MAS 经过实战与审计。**结论是不建议替换为通用 crate**——替换风险高于收益。真正的成本是：这套 crate 需跟随上游 MAS 的安全修复（如算法混淆/`alg=none`/JWK 注入类 CVE），而派生后已与上游脱钩。
- **建议**：
  1. 在 `jose/Cargo.toml` 或 crate 根 doc 注释中显式标注派生来源与对应的 MAS commit/版本，建立「定期 diff 上游安全补丁」的流程（当前 `lib.rs:1` 未见来源标注）。
  2. 不替换为 `josekit`/`jsonwebtoken`。仅核查 `jwt/signed/verify.rs` 是否强制 alg 白名单（防 alg-confusion），作为安全维度跟进项。
- **复验结论**：已确认 `jose`/`oauth-types` 模块结构与底层原语依赖、MAS 版权头属实；`jose/src/lib.rs:1` 无来源标注属实。本条为「记录 + 流程建议」，不主张替换。条目成立。

---

## 问题 3：手写 TOTP（RFC 6238/4226）—— 实现正确但生态有成熟 crate

- **严重级别**：P3
- **证据**：
  - `crates/backend/src/totp.rs`：手写 `generate_code`（HMAC-SHA1 + RFC 4226 §5.4 dynamic truncation，:30-37）与 base32 secret 解码、`SKEW_STEPS=1` 时间窗校验。直接 `use hmac::Hmac; use sha1::Sha1`。
- **影响**：实现本身符合 RFC（截断、取模、skew 窗口均正确）。但 TOTP 校验是认证关键路径，自实现意味着自行承担「constant-time 比较是否到位、skew 窗口是否引入重放窗口、base32 解码边界」等正确性责任；生态中 `totp-rs` 等 crate 已封装这些并被广泛使用。
- **建议**：评估替换为 `totp-rs`（或 `otpauth`），获得经测试的 base32/skew/防重放处理与 `otpauth://` URI 生成；若坚持自实现，确保 code 比较走 constant-time（当前用 `binary % 10^digits` 得到数值再比较 `u32`，相等比较对数值类型本身无 timing 泄漏，可接受），并补充防重放（同一 time-step 内已用过的 code 应拒绝）。
- **复验结论**：已重开 `totp.rs` 头 40 行确认 HMAC-SHA1 + 动态截断 + skew 逻辑属实。条目为「可选优化」。条目成立。

---

## 问题 4（正向 + 复用核查）：canonical-JSON 已正确复用 SDK；建议同样核查 wire 请求/响应体复用

- **严重级别**：P3
- **证据**：
  - canonical-JSON 全仓统一走 SDK：`handlers/contrix.rs:1663 contrix_core::canonical::canonical_sha256`、`handlers/account/agents.rs:371 canonical_sha256`、`services/soland_webvh.rs:341 contrix_core::canonical::canonical_json_bytes`、`services/policy_signer.rs:130 canonical_json_bytes`。无任何手写 `sort_keys`/BTreeMap 排序冒充 canonical（已用 `grep` 排查确认）。这是**应表扬的复用**——canonical-JSON 是签名一致性最易出错处。
  - 同时 `handlers/contrix.rs` 自定义了大量 wire DTO（`ServiceDescribeResponse:542`、`IdentityDescribeResBody:638`、`IdentityResolveResBody:649`、`DirectoryDescribeResBody:666`、`ResolveHandleResponse:674` …）。而 SDK `contrix-rust-sdk/crates/contracts/src/protocol` 已 re-export 一批 `*ReqBody/*ResBody`（spec_digest §5.3：`Directory*/Identity*` 等），`crates/core/src/model/` 亦有 `object_address`/`handle`/`runtime_identity` 等协议类型。
- **影响**：若 coauth 的 `IdentityResolveResBody`/`ResolveHandleResponse`/`DirectoryDescribeResBody` 与 SDK contracts 的对应 `*ResBody` 是同一跨服务 wire 契约的两份独立定义，会随 spec 演进产生 producer/consumer 漂移（正是 SDK contracts crate「准入规则」要防的场景）。
- **建议**：逐一核对 `handlers/contrix.rs` 中的 `Identity*ResBody`/`Directory*ResBody`/`ResolveHandle*` 与 SDK `contrix_contracts::protocol` 同名/同语义类型；凡属「spec 定义的跨服务 wire 契约且被 ≥2 repo 消费」者，改为复用 SDK 类型，删除 coauth 本地副本，消除漂移面。canonical-JSON 的良好复用模式应推广到 wire 类型层。
- **复验结论**：已确认四处 canonical 调用点均指向 `contrix_core::canonical`、无手写排序；`contrix.rs` 自定义 `*ResBody` 行号属实。SDK 侧对应类型存在性来自 spec_digest §5.3 锚点（未逐字段比对，故定级 P3 并表述为「需核查」）。条目成立。

---

## 附：确认为良好实践

- **canonical-JSON 全仓复用 SDK**，无手写排序冒充——直接消除了一类签名一致性 bug。
- 密码哈希复用 `argon2`/`bcrypt`/`pbkdf2` + `zxcvbn` 标准 crate，未自实现 KDF（见 `handlers/passwords.rs`）。
- TLS/HTTP 客户端用 `rustls` + `hyper-rustls` + `rustls-platform-verifier`，未自行实现证书校验。
