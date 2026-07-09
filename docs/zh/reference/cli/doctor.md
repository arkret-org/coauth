# `doctor`

运行部署诊断，帮助发现常见的配置和部署问题。

## 用法

```bash
coauth doctor -c config.yaml
```

## 检查项目

`doctor` 命令执行以下诊断：

- **配置有效性** — 检查配置文件的语法和语义
- **Issuer 检查** — 当配置的 issuer 不是 HTTPS 时给出警告
- **Principal Server 配置** — 输出 `arkret.principal_servers` 中配置的条目
- **OpenID discovery** — 请求 `/.well-known/openid-configuration` 并校验 issuer
- **Arkret discovery** — 请求 `/_arkret/describe`

## 输出说明

每个检查项显示一个状态：

- **OK** — 检查通过
- **WARN** — 检测到潜在问题，服务可能仍能运行
- **FAIL** — 发现严重问题，服务可能无法正常工作

## 使用建议

- 每次修改配置后运行 `doctor` 验证设置
- 使用 `RUST_LOG=debug` 获取更详细的诊断输出
