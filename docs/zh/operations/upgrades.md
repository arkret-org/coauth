# 升级

`coauth` 在 HTTP 契约上遵循 [SemVer](https://semver.org/)。Patch / minor
升级永远不会破坏 OIDC / OAuth / Arkret 已有 surface；major 升级会在至少
一个 minor 版本之前预先标记 deprecation。

## 常规升级流程

适用于同一 major 上的就地升级。

1. 阅读目标构建的发布说明，关注 `BREAKING:` 标记。
2. 用 `pg_dump` 做数据库快照（见 [备份与恢复](backup-restore.md)）。
3. 在 staging 环境拉取新镜像 / 二进制。
4. 显式跑迁移：

   ```sh
   coauth database migrate --config /etc/coauth/config.yaml
   ```

   迁移是幂等且仅向前的：旧二进制无法连接新 schema。
5. 先用新二进制启动一个副本，观察 `coauth doctor`、`/health` 与访问日志。
6. 滚动替换其余节点。
7. **保留上一版本的镜像 tag 至少 24 小时**，以便回滚只需要切 tag。

`coauth` 设计为水平扩展，所有 minor 升级都支持滚动重启。

## 兼容性范围

跟踪的兼容契约：

- `/.well-known/openid-configuration`
- `/.well-known/arkret/openapi.yaml`
- `/_coauth/admin/openapi.yaml`
- `/_cokret/describe` 与 `/_cokret/*` 其余路径
- CLI 子命令（`server`、`worker`、`manage`、`database`、`config`、
  `templates`、`doctor`）

minor 之间**可能**变化的：

- 内部 listener 路由（`/connection-info`、`/metrics`）。
- 模板变量；自定义模板需要在每次升级时 rebase。
- Cedar / OPA policy bundle。

## 回滚

升级成功后**不一定能安全回滚** —— 新 schema 的 NOT NULL 列旧二进制可能
不认。受支持的回滚路径是从升级前的 `pg_dump` 还原数据库。

每次 major 升级前都应当文档化一次回滚 runbook，并在 staging 上 dry-run。
