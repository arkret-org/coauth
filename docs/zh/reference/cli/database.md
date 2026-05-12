# `database`

数据库管理命令。

## `database migrate`

执行所有待应用的数据库迁移：

```bash
coauth database migrate -c config.yaml
```

### 使用场景

- **版本升级后** — 安装新版本 coauth 后，如果使用了 `--no-migrate` 标志，需要手动执行迁移
- **CI/CD 流水线** — 在部署新版本之前，作为单独步骤执行迁移
- **手动控制** — 不使用服务启动时的自动迁移，改为手动执行

### 故障恢复

如果迁移中途失败：

1. 查看日志确认具体错误
2. 修复底层问题（通常是数据库权限或约束问题）
3. 重新运行 `database migrate`，它会从失败处继续
