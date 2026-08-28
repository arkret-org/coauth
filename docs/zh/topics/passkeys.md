# Passkey

Coauth 支持面向人类 service account 的 username-first WebAuthn / Passkey
登录。Passkey 是抗钓鱼的账号认证器，但不是 Arkret DID principal 密钥、
DPoP 密钥、已登记设备密钥或 agent runtime proof。

## 用户流程

- 在登录页输入账号 handle 并继续，然后选择“使用 Passkey 登录”。断言验证
  成功后会建立标准 Coauth 浏览器会话，并可继续原有 OAuth/OIDC 授权流程。
- 最近完成认证的用户可在“安全中心”添加、查看、重命名和吊销自己的
  Passkey。
- 注册 finish 不接受 account id 或 handle；注册的两个请求都从当前有效
  浏览器会话派生账号。
- Coauth 阻止吊销账号的最后一个 Passkey。移除前应先建立第二个 Passkey。
- 管理 API 不提供向他人账号静默植入管理员控制 Passkey 的端点。

添加、重命名和吊销要求最近十分钟内完成过认证。凭据列表只暴露 Coauth
内部 ID、标签、创建/最近使用时间、用户验证状态与同步提示，不暴露公钥或
完整 WebAuthn credential ID。

## 部署要求

WebAuthn 与 Origin 绑定。生产部署必须使用 HTTPS，并正确配置 Coauth 的
外部公开 URL；仅本地开发支持 `localhost` HTTP。

Coauth 启动时从公开 URL 派生 RP ID 和 RP Origin。若两者无效或不一致，
WebAuthn 服务不会发布，`passkey_login_enabled` 为 false。不得通过放宽
Origin 绕过此失败；应修复外部 URL、反向代理头和稳定 RP ID。所有副本必须
连接同一个 PostgreSQL 数据库。

待完成 ceremony 在 PostgreSQL 中保存十分钟，并由 finish 原子删除。因此
start/finish 可落到不同副本，也支持多标签页与进程重启；重放、浏览器 cookie
置换、用途置换和过期请求都会失败关闭。

Passkey 路由是同源账号接口，不是开放 credentialed CORS 的公共接口。
ceremony 使用加密的 `HttpOnly`、`SameSite=Lax` cookie 绑定浏览器（HTTPS 下
同时设置 `Secure`）；变更请求使用 JSON，并按操作要求校验有效或 recent
browser session。Coauth 会拒绝 `Origin` 或 `Sec-Fetch-Site` 表明请求来自
不同源的浏览器请求。start/finish 复用现有按 IP 和账号的登录限流，每个
ceremony 只能消费一次。应保持 Coauth CSP，不在登录页和安全中心加载第三方
脚本，也不得在反向代理上为这些路由配置带凭据的通配 CORS。

生产启用 Passkey 前必须逐项确认：

- 浏览器可见 URL 使用 HTTPS（仅字面量 `localhost` 开发环境可使用 HTTP）、
  保持稳定，并与 `http.public_base_url` 完全一致；
- 公开主机名就是预期 RP ID，且不是 IP 字面量；
- 反向代理保持配置的外部 scheme/host，只允许同源浏览器访问 Passkey 账号
  路由，并且不以更弱的值覆盖 Coauth CSP 或 cookie 属性；
- 所有副本使用相同公开 URL、cookie secret、配置和 PostgreSQL 数据库，同时
  对各监听器分别执行健康检查；
- 在限制密码/OIDC 回退前，先通过生产反向代理完成一次真实注册与登录。

公开 URL/RP 配置无效时，服务通过不发布 Passkey capability 失败关闭；
Origin、浏览器绑定、用途置换、过期与重放则在请求或 ceremony 边界失败。

## 威胁模型与控制

- 注册账号只从当前有效 browser session 派生；请求 hint 不能给他人账号绑定
  credential，管理员也没有静默植入凭据的端点。
- 认证 finish 只从 durable、单次消费的 ceremony 派生账号；仅知道 opaque
  ceremony ID、没有加密浏览器绑定 cookie 时无法完成。
- `webauthn-rs` 校验 RP ID、精确 Origin、challenge、签名、UP 与 UV；Coauth
  额外校验过期、用途、账号/session 绑定，并用 compare-and-set 更新计数器。
- 签发标准 browser session 前再次检查账号状态。OAuth continuation 继续使用
  既有服务端 grant、redirect URI、PKCE、state/nonce 与 consent 管线，不产生
  第二套 Passkey bearer grant。
- 生命周期 API 和审计元数据不返回/记录 credential 完整 ID、公钥、assertion、
  `clientDataJSON` 或 `authenticatorData`；审计只使用 Coauth 内部 Passkey ID
  和风险标志。
- 吊销在 PostgreSQL 内按账号串行化，两个并发请求不能同时删掉最后两个
  Passkey。
- username-first 流程仍可能通过 ceremony 成功/失败暴露某个 handle 是否有
  可用 Passkey。IP/账号限流可降低批量探测；需要更强标识隐私的部署应等待
  另行评审的 discoverable-credential 流程。
- 同源 XSS 即使读不到 `HttpOnly` cookie，仍可能发起浏览器动作。因此 CSP、
  依赖审查和认证页面不加载第三方脚本仍属于安全边界。

## 认证器与恢复边界

登录强制要求 authenticator 的用户验证（UV）标志。Coauth 记录 BE/BS，
以区分同步 Passkey 与设备绑定 security key 的风险差异；当前不执行
attestation 型号 allow-list，也不声明 AAL3。

实现使用标准浏览器 WebAuthn API，目标覆盖平台认证器、漫游 USB/NFC
security key 与浏览器中介的跨设备流程，但每个部署仍须用自己的浏览器和
认证器矩阵验证，本文不构成设备认证清单。

当前自动兼容门禁实际覆盖 Windows 上的 Chrome 150，以及 CDP CTAP2
虚拟平台认证器（resident key、UV、自动 presence）。Windows Hello、
Safari/iCloud Keychain、Chrome/Google Password Manager、USB/NFC 漫游密钥
和 hybrid QR transport 是标准目标，但尚未进入本仓库自动验证矩阵。

密码和邮箱恢复可能弱于 Passkey。恢复只重新获得 Coauth service account
访问权，不会恢复或轮换 DID identity root，也不会自动授权新的 Arkret
设备。支持与事故流程必须明确提示这种保证降级。

吊销 Passkey 会阻止该凭据发起新的 assertion，但不会静默吊销已经建立的
browser session、OAuth session 或 proof-bound session grant。事故响应需要
终止既有会话时，应使用已有 session/device 吊销能力，或锁定/停用账号。
密码/邮箱恢复及 recovery generation 变化同样不会轮换或复活 Passkey：
有效凭据继续有效，已吊销凭据继续保持吊销。
