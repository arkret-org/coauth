# 备份与恢复

`coauth` 的所有权威状态都保存在 Postgres 中。**只要备份了数据库、签名密钥
和加密密钥**，就足以完整恢复一个部署。

## 必须备份的内容

| 项目 | 位置 | 说明 |
| --- | --- | --- |
| Postgres 数据库 | `database.uri` | 用户、会话、OAuth client、审计日志等。 |
| 加密运行时密钥包 | `secrets.path` | 同时包含长期 JWS 私钥和应用加密密钥；丢失会使 token 失效并使加密状态不可读。 |
| KeyStore master key | `secrets.master_key_file`（或外部 secret source） | 必须与加密密钥包配套恢复，并应分开备份。 |
| 配置 | `config.yaml` | 当作源代码处理：放进私有仓或密钥管理系统。 |
| 自定义模板 / 策略 | `templates.path`、`policy.path` | 可选，默认随容器镜像和 `share/` 一同发布。 |

> **数据库 + 加密 KeyStore 文件 + master key** 是最小可恢复集合。少一个都算不完整。

## Postgres dump

```sh
pg_dump \
  --no-owner --no-privileges \
  --format=custom \
  --file=/var/backups/coauth-$(date -u +%Y%m%dT%H%M%SZ).dump \
  "$DATABASE_URL"
```

用 cron / systemd-timer 调度。**备份在离开主机前必须加密**（例如
`age --encrypt --recipient ...`），里面包含密码哈希、refresh-token 哈希、
OAuth client 密钥和恢复凭证。

## 恢复流程

1. 准备一台新的 Postgres 实例，建立空目标库。
2. `pg_restore --create --clean --no-owner --no-privileges --dbname=postgres dump.bin`。
3. 把 encrypted KeyStore 文件与单独托管的 master key **逐字节地**还原到新主机；
   两者缺一都无法恢复签名密钥和应用加密密钥。
4. 还原 `config.yaml`，仅修改 `database.uri`。
5. `coauth database migrate --config /etc/coauth/config.yaml`。
6. 启动服务并观察 `coauth doctor` 输出。

## 没演练过的备份不算备份

至少每月一次把备份还原到一台抛弃环境，跑一遍：

```sh
coauth database check --config /etc/coauth/config.yaml
coauth doctor          --config /etc/coauth/config.yaml
```

## 灾难恢复 checklist

- [ ] 备份文件分布在两个不同地理位置。
- [ ] 离机存储的备份**用不在 coauth 主机上的密钥加密**。
- [ ] 每月至少一次完整恢复演练。
- [ ] On-call 操作人员的联系路径文档化。
- [ ] 恢复流程不依赖某一个具体的人。
