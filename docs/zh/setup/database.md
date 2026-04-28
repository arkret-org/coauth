# 数据库设置

Pasion 使用 **PostgreSQL** 作为唯一的数据存储后端。

## 要求

- PostgreSQL **13** 或更高版本
- 建议使用专用数据库用户
- 数据库用户需要拥有建表、建索引等 DDL 权限（用于自动迁移）

> **注意：** 如果你使用数据库连接池工具（如 PgBouncer），请确保使用 **session** 模式而非 **transaction** 模式。Transaction 模式不支持 Pasion 使用的某些 PostgreSQL 特性（如 `LISTEN/NOTIFY`）。

## 创建数据库

```sql
CREATE USER coauth WITH PASSWORD '你的密码';
CREATE DATABASE coauth WITH OWNER coauth;
```

## 配置连接

在配置文件中设置数据库连接信息：

```yaml
database:
  uri: postgresql://coauth:你的密码@localhost/coauth
  # 可选：最大连接数
  max_connections: 10
  # 可选：最小空闲连接数
  min_connections: 0
  # 可选：连接超时时间
  connect_timeout: 30
```

## 数据库迁移

Pasion 使用自动迁移机制管理数据库架构。默认情况下，`coauth server` 启动时会自动应用所有待执行的迁移。

如果你希望手动控制迁移过程：

```bash
# 使用 --no-migrate 标志启动服务器
coauth server --no-migrate -c config.yaml

# 手动执行迁移
coauth database migrate -c config.yaml
```

## 备份建议

- 定期备份数据库，建议使用 `pg_dump` 进行逻辑备份
- 在执行版本升级前，务必先备份数据库
- 考虑配置 PostgreSQL 的持续归档（WAL archiving）以实现时间点恢复
