# coauth 审查报告 12：其他发现的问题

> 被审项目：`D:/Works/contrix-dev/coauth`（Contrix Auth/Account Server，MAS 派生，约 33.6 万行 / 18 crate）。
> 本报告收录不属于结构（04）/选型（07）维度、但值得修正的工程问题：错误处理 panic 风险、可观测性、配置、测试缺口、依赖/构建隐患等。

## 审查范围

实际通读 / 检索的路径（相对 `coauth/`）：

- panic-prone 调用统计：全 crate `grep '.unwrap()|.expect('`（去 test 后 backend 约 249 处）、`panic!/unreachable!/todo!/unimplemented!`（非 test 上下文逐条核对）。
- 配置驱动 panic：`crates/backend/src/handlers/flow/definition.rs:129-138`（designation match）、`:184-189`（identification field match），及其来源 `FlowDefinitionFile`（YAML 反序列化，:1-40 doc）。
- registration 路径 panic：`crates/backend/src/handlers/account/service/registration.rs:2186 unreachable!()`。
- 重试循环 `unreachable!`：`crates/backend/src/outbound_http.rs:604`。
- TOTP expect：`crates/backend/src/totp.rs:24`。
- 测试覆盖：逐 crate 统计含 `#[test]/#[cfg(test)]/#[tokio::test]` 的源文件数与 `tests/` 目录。
- 可观测性：`grep tracing_subscriber|opentelemetry|metrics::`、`telemetry.rs`。
- 配置安全默认：`config.example.yaml`、`crates/config/src/sections/`。
- 秘密日志风险：`grep '(debug|info|warn|error)!\(.*password|secret|token'`。
- workspace lint 策略：root `Cargo.toml`（`dead_code="allow"`、clippy pedantic 大量 `allow`）。
- v2+ 漂移：`grep 'v2|V2|_v2'`（结果全为外部 API，无协议漂移）。

复验命令：
```
grep -rn -E 'panic!\(|unreachable!\(' crates/backend/src | grep -viE 'test'
sed -n '129,189p' crates/backend/src/handlers/flow/definition.rs
sed -n '2180,2191p' crates/backend/src/handlers/account/service/registration.rs
for d in crates/*/; do grep -rl '#\[cfg(test)\]\|#\[test\]\|#\[tokio::test\]' "$d/src" | wc -l; done
```

未覆盖：249 处非 test `unwrap/expect` 未逐条核对（抽样确认多数在 `Duration::try_*().unwrap()`、`Mutex::lock().unwrap()` 等惯用安全场景）；CI workflow（`.github/workflows/`、`.gitea/`）未逐行读，仅看到 README 描述的 gitleaks/fmt/clippy 门禁。优先覆盖了 panic 风险、测试缺口、可观测性与 lint 策略。

## 结论摘要

错误处理整体克制（关键认证路径如 `oidc_bridge.rs` 已用 `grep` 确认无裸 unwrap）。但存在**两类生产 panic 风险**：(1) 用户可控的 YAML flow 定义会触发 `panic!`；(2) registration 路径有一处对 error 变体的 `unreachable!()`。测试覆盖**严重不均**：安全相关的 `policy` crate（1390 行，Cedar 授权）、`iana`、`keystore/src` 几乎无单元测试，`frontend`（8816 行）仅 1 个测试文件。workspace 全局 `dead_code="allow"` 掩盖死代码累积。本报告保留 **6** 条问题，最高 **P2**。

---

## 问题 1：用户可控的 YAML flow 定义触发 `panic!`（DoS / 配置即崩溃）

- **严重级别**：P2
- **证据**：
  - `crates/backend/src/handlers/flow/definition.rs:129-138`：`FlowDefinitionFile::into_flow` 把 `self.designation: String` 做 `match`，未知值落到 `other => panic!("unknown flow designation: {other}")`。
  - 同文件 `:184-189`：identification field 同样 `other => panic!("unknown identification field: {other}")`。
  - 来源：文件头 doc（`:1-26`）明确说明 `FlowDefinitionFile` 是「YAML-friendly representation … allows flows to be defined in configuration files」，且 `#[derive(Deserialize)]`（:54 附近）——`designation`/`user_fields` 是从**外部 YAML/JSON 配置反序列化**的自由字符串。
- **影响**：运维写错一个 `designation:` 拼写（如 `registratoin`）或使用了未支持的 identification field，服务在加载/解析 flow 配置时直接 `panic!` 崩溃，而非返回可诊断的配置错误。属「配置即崩溃」，可观测性差且在多副本部署下可能 crash-loop。
- **建议**：把两处 `into_flow` 改为返回 `Result<…, FlowDefinitionError>`，未知 `designation`/field 映射为 `Err`（携带原始字符串），由配置加载层统一报错并拒绝启动/拒绝该 flow。`StageDefinition::into_stage_kind`（:174）同理。
- **复验结论**：已重开 `definition.rs:129-138`、`:184-189` 与文件头 doc 确认 `panic!` 与「来自配置反序列化」属实。条目成立。

---

## 问题 2：registration finish 路径对 error 变体使用裸 `unreachable!()`

- **严重级别**：P2
- **证据**：
  - `crates/backend/src/handlers/account/service/registration.rs:2185-2187`：在对 `CheckRegistrationFinishEligibilityError` 的 `match` 中，`PrincipalServerUnavailable(_) => unreachable!()`——无任何说明为何不可达，且丢弃了内层 payload。
- **影响**：`PrincipalServerUnavailable` 是一个被显式定义的 error 变体（说明业务上确实可能产生）。一旦上游 eligibility 检查在某条路径下返回该变体（重构、新增调用点、或 principal server 真的不可用），此处会 panic 终止 registration 请求线程，而非返回 503/可重试错误。这是「靠当前调用图为真维持的隐式不变量」，极脆弱。
- **建议**：把该臂改为返回结构化错误，例如 `return Err(RegistrationFinishError::Internal(AnyhowError::msg("principal server unavailable during registration finish")))`，或映射为 `RegistrationFinishOutcome::Rejected`/503。若确证不可达，至少改 `unreachable!("…原因说明…")` 并加 debug_assert 与日志。
- **复验结论**：已重开 `registration.rs:2180-2191` 确认 `PrincipalServerUnavailable(_) => unreachable!()` 属实、无注释。条目成立。

---

## 问题 3：安全相关 crate 测试覆盖严重不足（policy / keystore / iana 几无单测）

- **严重级别**：P2
- **证据**（逐 crate 统计含测试宏的源文件数）：
  - `policy`：**src 测试文件 = 0**（crate 1390 行，含 `cedar.rs` Cedar 授权评估、`remote.rs` 远程策略、`audit.rs`、`provider.rs`——授权决策是安全核心）。
  - `keystore`：src 测试文件 = 0（仅 `tests/` 目录 1 个集成测试）。
  - `iana`：src 测试文件 = 0（IANA JOSE 算法注册表，被 jose/keystore 依赖）。
  - 对比覆盖良好者：`backend` 97、`data` 21、`oauth-types` 11、`admin-types` 11、`config` 8、`jose` 6。
- **影响**：`policy` crate 是鉴权判定的核心（Cedar 策略求值 + 远程 fallback），零单元测试意味着策略允许/拒绝逻辑、default-effect、远程降级行为缺乏回归保护——授权是 IdP 最不能回归的部分。`keystore` 的密钥选择/算法匹配同样无 src 级测试。
- **建议**：为 `policy` 补单元测试：Cedar 允许/拒绝/默认效果、`remote` provider 超时/错误降级语义、`audit` 记录路径。为 `keystore` 补「按 alg 选 key」「缺 key 返回 None」测试（恰好覆盖报告 07 问题 1 的密钥优选不变量）。
- **复验结论**：已用 `grep -rl '#\[cfg(test)\]\|#\[test\]\|#\[tokio::test\]' crates/<x>/src | wc -l` 复核 policy/keystore/iana 计数为 0、backend/data 等非 0。条目成立。

---

## 问题 4：`frontend` crate（8816 行）几乎无测试

- **严重级别**：P3
- **证据**：
  - `frontend`：src 测试文件 = 1，`wasm_bindgen_test` 命中也仅 1 个文件（`grep -rl '#\[test\]\|#\[wasm_bindgen_test'`）。crate 规模 8816 行（含 `pages/register.rs` 990 行等）。
- **影响**：登录/注册/同意等用户面 SPA 逻辑（leptos）几乎无自动化测试，表单校验/状态机回归只能靠人工或 e2e 捕获，迭代风险高。
- **建议**：至少对 SPA 内的纯逻辑（表单校验、状态转换、URL/参数解析）抽出可在原生 target 测试的纯函数并补单测；交互层用 `wasm-bindgen-test` 覆盖关键 happy/error path。
- **复验结论**：已复核 frontend 测试文件计数 = 1。条目成立。

---

## 问题 5：workspace 全局 `dead_code = "allow"` 掩盖死代码累积

- **严重级别**：P3
- **证据**：
  - root `Cargo.toml` `[workspace.lints.rust]`：`dead_code = "allow"`，注释自述理由是「many helpers/fields/types are public-API surface the warning can't see through」。
  - 同段 `[workspace.lints.clippy]` 还把 pedantic 下 20+ 项设为 `allow`（`unnecessary_wraps`、`unused_async`、`too_many_lines`、`needless_pass_by_value`…）。
- **影响**：`dead_code="allow"` 是全 workspace 一刀切，代价是真正的死代码（未被任何路径调用的 helper/分支）无法被编译器发现，长期累积膨胀（这与 04 报告的超大文件互为因果）。注释承认「When a helper is truly dead, delete it」，但关掉 lint 后无人会被提醒去删。
- **建议**：把 `dead_code` 从 workspace 级 `allow` 收回，改为在确属「外部 API / codegen / 条件编译消费」的具体 item 上加 `#[allow(dead_code)]` 或 `pub`，让编译器恢复对真死代码的提示；或定期跑一次 `dead_code="warn"` 做清理审计。`unused_async` 同理（可掩盖本不必 async 的函数）。
- **复验结论**：已重开 root `Cargo.toml` lint 段确认 `dead_code="allow"` 及其注释、clippy allow 列表属实。条目成立。

---

## 问题 6：`outbound_http` 重试循环以裸 `unreachable!` 收尾 + `totp` 用 `expect`（低风险，但建议消除）

- **严重级别**：P3
- **证据**：
  - `crates/backend/src/outbound_http.rs:604`：`unreachable!("outbound retry loop must return from the final attempt")`。审阅 `:593-603` 循环体，`attempt < max_attempts` 控制下每条分支（成功/终态错误/最后一次错误）都 `return`，逻辑上确不可达——但仍是「靠循环边界正确性维持」的 panic 点。
  - `crates/backend/src/totp.rs:24`：`HmacSha1::new_from_slice(secret).expect("HMAC accepts any key length")`——HMAC 确实接受任意长度 key，此 expect 实际不会触发。
- **影响**：两处均为「当前不可达」，风险低；但裸 `unreachable!`/`expect` 是潜在 panic 源，一旦上游重构（如改循环条件、改 HMAC 类型）会变成生产 crash。
- **建议**：`outbound_http.rs:604` 改为把循环写成可静态保证返回的形式（如 `for attempt in 1..=max_attempts { … }` 后返回最后一次结果，而非 `loop` + unreachable）。`totp.rs:24` 的 `expect` 可保留（语义恒真），或改为返回 `Result` 与上层错误统一。
- **复验结论**：已重开 `outbound_http.rs:580-604` 确认每分支 return、`totp.rs:24` expect 字面属实。条目成立。

---

## 附：确认为「非问题 / 已做对」

- **关键认证路径无裸 unwrap**：`handlers/account/auth/oidc_bridge.rs`、`handlers/account/oidc_bridge.rs` 经 `grep` 确认无非 test `unwrap`。
- **无协议版本漂移（v2+）**：所有 `v2/V2` 命中均为外部 API（RecaptchaV2、第三方邮件 `/v2/email`、Tencent `2021-01-11`），coauth 自身协议保持 v1，符合硬规则。
- **无秘密日志泄漏**：未发现把 `password/secret/client_secret/bearer/private_key` 直接写入 tracing 宏的实例（CLI 中 `error!("That password is too weak")` 仅文案，不含值）。
- **配置秘密管理规范**：`config.example.yaml` 全部用 `${ENV_VAR}` 占位，CI 有 gitleaks 门禁（README 描述）。
- **可观测性基础存在**：backend 广泛使用 `tracing`/`metrics`，有 `telemetry.rs`、`activity_tracker`。
