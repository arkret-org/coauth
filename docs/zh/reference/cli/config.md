# `config`

配置文件管理命令。

## `config generate`

生成一个带有合理默认值的配置文件：

```bash
coauth config generate > config.yaml
```

生成结果不包含私钥。配置好 durable KeyStore 后，使用一次
`coauth server --first-provisioning` 将完整运行时密钥包写入存储；后续启动不再带此
参数。

## `config check`

验证配置文件的语法和语义正确性：

```bash
coauth config check -c config.yaml
```

## `config dump`

输出合并后的完整配置（包括所有默认值）：

```bash
coauth config dump -c config.yaml
```

## `config sync`

将配置文件中的 OAuth 客户端和上游提供商定义同步到数据库：

```bash
coauth config sync -c config.yaml

# 试运行（不实际修改）
coauth config sync --dry-run -c config.yaml

# 删除数据库中不在配置文件中的项目
coauth config sync --prune -c config.yaml
```
