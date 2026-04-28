# 获取访问令牌

本页介绍如何通过命令行获取 Pasion 管理 API 的访问令牌。

## 使用设备码流程

仓库在 `misc/` 中提供了现成脚本来执行设备码授权流程（Device Code Grant）：

```bash
# macOS / Linux
sh ./misc/device-code-grant.sh https://auth.example.com/ urn:coauth:admin
```

```powershell
# Windows PowerShell / PowerShell 7+
pwsh -File ./misc/device-code-grant.ps1 https://auth.example.com/ urn:coauth:admin
```

## 使用客户端凭据流程

如果你有配置好的 OAuth 2.0 客户端：

```bash
TOKEN=$(curl -s -X POST https://auth.example.com/oauth2/token \
  -d "grant_type=client_credentials" \
  -d "client_id=你的客户端ID" \
  -d "client_secret=你的客户端密钥" \
  -d "scope=urn:coauth:admin" \
  | jq -r '.access_token')
```

## 常用作用域

| 作用域 | 说明 |
|--------|------|
| `urn:coauth:admin` | Pasion 管理 API 完全访问权限 |
| `urn:palpo:admin:api` | Palpo 管理 API 访问权限 |
| `urn:matrix:client:api:*` | Matrix 客户端 API 完全访问权限 |

## 注意事项

- 访问令牌有过期时间（默认 5 分钟），过期后需要重新获取
- 管理 API 的访问令牌应安全存储，不要泄露给未授权的用户
- 建议在自动化脚本中使用客户端凭据流程，在交互式场景中使用设备码流程
