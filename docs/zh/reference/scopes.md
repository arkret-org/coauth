# OAuth 2.0 作用域

Pasion 支持以下 OAuth 2.0 作用域（scope）。客户端在请求授权时可以指定一个或多个作用域。

## OpenID Connect 标准作用域

| 作用域 | 说明 |
|--------|------|
| `openid` | OpenID Connect 基本身份认证（必须） |
| `profile` | 获取用户的基本资料（显示名称等） |
| `email` | 获取用户的电子邮箱地址 |

## Matrix 相关作用域（MSC2967）

| 作用域 | 说明 |
|--------|------|
| `urn:matrix:client:api:*` | Matrix 客户端 API 完全访问权限 |
| `urn:matrix:client:api:guest` | Matrix 客户端 API 访客权限 |

## Palpo 专属作用域

| 作用域 | 说明 |
|--------|------|
| `urn:palpo:admin:api` | Palpo 管理 API 访问权限 |

## Pasion 管理作用域

| 作用域 | 说明 |
|--------|------|
| `urn:coauth:admin` | Pasion 管理 API 完全访问权限（旧版 `urn:mas:admin` 仍兼容支持） |
| `urn:mas:admin:read` | Pasion 管理 API 只读权限 |

## 作用域与策略

默认策略对作用域的处理规则：

- `urn:coauth:admin`（或旧版 `urn:mas:admin`） — 仅授予配置文件中 `policy.data.admin_clients` 列表中的客户端
- `urn:palpo:admin:api` — 同上
- 其他作用域 — 默认允许所有客户端请求

你可以通过[自定义策略](../topics/policy.md)修改这些规则。
