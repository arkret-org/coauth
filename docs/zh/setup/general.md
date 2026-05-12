# 基本配置

## 生成初始配置

服务启动前需要准备签名密钥、加密密钥、数据库配置，以及 Contrix 部署元数据。

用生成器输出一份带默认值的完整配置：

```bash
coauth config generate > config.yaml
```

生成结果会比较冗长。实际部署时通常只保留你要覆盖的配置段，把未修改的默认项删掉。

## 几乎一定会改的配置段

- `http.public_base`
- `database`
- `contrix.principal_servers`
- `contrix.identity_registry`
- `contrix.service_did`
- `contrix.issuer_did`
- `contrix.admin_audience`
- `secrets`
- `passwords`

## 校验配置

```bash
coauth config check --config=config.yaml
```

## 查看合并后的最终配置

```bash
coauth config dump --config=config.yaml
```

配置文件的加载优先级如下：

1. 所有通过 `--config` 显式传入的文件
2. 否则读取环境变量 `PASION_CONFIG`，并按 `:` 分隔
3. 否则读取当前工作目录下的 `config.yaml`

环境变量覆盖也仍然沿用 legacy `PASION_` 前缀，并使用 `__` 作为层级分隔符，例如：

```bash
PASION_EMAIL__PROVIDER__TYPE=resend
PASION_EMAIL__PROVIDER__API_KEY=re_xxxxxxxxx
```

## 编辑器 Schema

生成的 JSON Schema 位于 `docs/config.schema.json`。如果你修改了 Rust 配置模型，可以用：

```bash
cargo run -p coauth-config --bin schema > docs/config.schema.json
```

在 VS Code 等支持 YAML Schema 的编辑器里，可以这样引用：

```yaml
# yaml-language-server: $schema=./docs/config.schema.json
```

## 同步配置型数据库状态

以下配置段会在启动时同步到数据库，最常见的是：

- `clients`
- `upstream_oauth2`

也可以手动执行：

```bash
coauth config sync
```

如果希望数据库里被删除的条目也一起清理，追加 `--prune`。
