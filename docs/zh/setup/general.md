# 基本配置

## 生成配置文件

使用 `config generate` 命令生成一个带有合理默认值的配置文件：

```bash
coauth config generate > config.yaml
```

生成的配置文件包含所有可用选项及其默认值。你需要根据实际部署环境修改以下关键设置：

- 数据库连接信息
- 公开访问的 URL（`http.public_base`）
- 加密密钥和签名密钥
- Matrix homeserver 地址

## 验证配置

使用 `config check` 命令验证配置文件的正确性：

```bash
coauth config check -c config.yaml
```

## 查看最终配置

使用 `config dump` 命令查看合并后的完整配置（包括默认值）：

```bash
coauth config dump -c config.yaml
```

环境变量覆盖使用 `PASION_` 前缀，并以 `__` 作为层级分隔符。例如：
`PASION_EMAIL__PROVIDER__TYPE=resend` 和
`PASION_EMAIL__PROVIDER__API_KEY=re_xxxxxxxxx`。

## 编辑器支持

Pasion 提供 JSON Schema 文件，可以在支持的编辑器中获得自动补全和验证。配置文件的 JSON Schema 位于 `docs/config.schema.json`。

### VS Code

在配置文件的 YAML 头部添加以下注释即可启用自动补全：

```yaml
# yaml-language-server: $schema=./docs/config.schema.json
```

## 密钥管理

配置文件中的敏感信息（如加密密钥、数据库密码等）可以通过以下方式提供：

- **内联** — 直接写在配置文件中（适合开发环境）
- **文件引用** — 引用外部文件中的密钥内容（推荐用于生产环境）
- **环境变量** — 通过环境变量注入（适合容器化部署）

详细的配置选项请参阅[配置文件参考](../reference/configuration.md)。
