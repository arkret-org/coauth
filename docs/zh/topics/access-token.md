# 获取访问令牌

`coauth` 在 `misc/` 中提供了脚本，用 OAuth 2.0 Device Authorization Grant
为 CLI 或管理员场景交互式获取访问令牌：

- `misc/device-code-grant.sh` 面向 POSIX shell，需要 `sh`、`jq` 和 `curl`。
- `misc/device-code-grant.ps1` 面向 Windows PowerShell / PowerShell 7，不依赖
  `jq`。

脚本会读取标准 OIDC discovery 文档
`/.well-known/openid-configuration`，动态注册 native public client，并在未显式传入
scope 时默认请求 `urn:coauth:admin`。

```bash
sh ./misc/device-code-grant.sh https://auth.example.com/
```

```powershell
pwsh -File ./misc/device-code-grant.ps1 https://auth.example.com/
```

脚本会输出验证 URL 和用户码。你在浏览器中完成授权后，脚本会打印 token response。

## 常用 scope

访问稳定的 coauth admin API 时使用 `urn:coauth:admin`：

```bash
sh ./misc/device-code-grant.sh https://auth.example.com/ urn:coauth:admin
```

Contrix-native 集成应使用 Contrix scope：

```bash
sh ./misc/device-code-grant.sh https://auth.example.com/ urn:contrix:admin:* urn:contrix:principal-server:session.bind
```

## 自动化

非交互式自动化应优先使用 OAuth 2.0 client credentials grant，并配置 confidential
client：

```bash
TOKEN=$(curl -sS -X POST https://auth.example.com/oauth2/token \
  -d "grant_type=client_credentials" \
  -d "client_id=${CLIENT_ID}" \
  -d "client_secret=${CLIENT_SECRET}" \
  -d "scope=urn:coauth:admin" \
  | jq -r '.access_token')
```

访问令牌默认是短生命周期。请把它们作为 secret 存储，并在自动化下线时撤销对应 session
或 client credential。
