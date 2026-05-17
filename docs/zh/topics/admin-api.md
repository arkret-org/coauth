# 使用管理 API

`coauth` 提供 REST-like 管理 API，供管理员、`sodmin` 和受信任的自动化系统管理账号、
会话、设备、claim、OAuth 客户端、通知渠道、连接器和策略数据。

管理 API 默认不暴露。需要在 `http.listeners` 的 `resources` 中启用 `adminapi`。所有请求
都必须携带具备 `urn:coauth:admin` 或 `urn:contrix:admin:*` 的访问令牌。

## API 文档

完整 API 文档以 OpenAPI 规范提供。启用 `adminapi` 后，运行时会暴露这些路径：

- `GET /api/admin/v1/openapi.yaml`：Contrix-native 管理 API 合约。
- `GET /.well-known/contrix/openapi.yaml`：供 `sodmin` 和服务自动化发现。
- `GET /api-doc/admin/openapi.json`：兼容 Swagger 工具的 JSON 版本。
- `GET /admin-swagger-ui/`：服务内置 Swagger UI。

Contrix-native 管理面现在包含 `GET /api/admin/v1/accounts`、
`GET /api/admin/v1/accounts/{id}`、`POST /api/admin/v1/accounts/{id}/lock` 和
`POST /api/admin/v1/accounts/{id}/disable`。DID binding、设备管理、claim
签发/吊销、policy dry-run 和 signed policy decision audit 路由已经进入 OpenAPI，
并作为受保护端点提供。设备清单从已持久化的 session grant 和设备吊销审计记录派生；
policy dry-run 会持久化 signed decision audit record，随后可通过 decision-audit
路由查询。

## 认证方式

管理 API 支持两种认证方式：

### 1. 交互式认证

使用浏览器会话进行认证。适合通过 Web 界面手动管理：

```bash
# 先通过设备码流程获取令牌
sh ./misc/device-code-grant.sh https://auth.example.com/ urn:coauth:admin
```

### 2. OAuth 令牌

使用客户端凭据流程获取管理 API 的访问令牌：

```bash
curl -X POST https://auth.example.com/oauth/token \
  -d "grant_type=client_credentials" \
  -d "client_id=你的客户端ID" \
  -d "client_secret=你的客户端密钥" \
  -d "scope=urn:coauth:admin"
```

## 响应格式

管理 API 借鉴 JSON:API 形状，列表、详情和错误响应都使用稳定 envelope。

### 成功响应

```json
{
  "data": {
    "type": "user",
    "id": "01HFRQFT5QFBM3Y5BHNFHMP6M0",
    "attributes": {
      "username": "alice"
    }
  }
}
```

### 分页

列表端点使用基于游标的分页：

```bash
# 获取前 10 个用户
curl "https://auth.example.com/api/admin/v1/users?page[first]=10"

# 使用游标获取下一页
curl "https://auth.example.com/api/admin/v1/users?page[first]=10&page[after]=游标值"
```

响应中包含分页信息：

```json
{
  "meta": {
    "count": 42
  },
  "links": {
    "self": "/api/admin/v1/users?page[first]=10",
    "next": "/api/admin/v1/users?page[first]=10&page[after]=01H..."
  }
}
```

会话和 session grant 端点只暴露 client ID、audience、scope、过期时间、吊销状态和
last activity 等元数据。列表和详情响应不会返回已存储的 JWT、refresh token、session
private key 或 provider secret。Personal access token 只会在创建或重新生成时返回一次。

## 常用操作

### 列出所有账号

```bash
curl -H "Authorization: Bearer $TOKEN" \
  https://auth.example.com/api/admin/v1/accounts
```

### 锁定账号

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" \
  https://auth.example.com/api/admin/v1/accounts/$ACCOUNT_ID/lock
```

### 终止会话

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" \
  https://auth.example.com/api/admin/v1/user-sessions/$SESSION_ID/finish
```

### 吊销 personal session

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" \
  https://auth.example.com/api/admin/v1/personal-sessions/$SESSION_ID/revoke
```
