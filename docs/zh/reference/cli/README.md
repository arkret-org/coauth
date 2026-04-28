# 命令行工具

Pasion 通过 `coauth` 命令行工具进行管理和操作。

## 基本用法

```bash
coauth [全局选项] <子命令> [选项]
```

## 全局选项

| 选项 | 说明 |
|------|------|
| `-c, --config <FILE>` | 指定配置文件路径 |
| `-h, --help` | 显示帮助信息 |
| `-V, --version` | 显示版本号 |

## 子命令

| 命令 | 说明 |
|------|------|
| [`server`](./server.md) | 启动认证服务 |
| [`worker`](./worker.md) | 启动后台任务 Worker |
| [`config`](./config.md) | 配置文件管理（生成、检查、同步） |
| [`database`](./database.md) | 数据库操作（迁移） |
| [`manage`](./manage.md) | 用户和账户管理 |
| [`doctor`](./doctor.md) | 运行部署诊断 |

## 日志级别

通过 `RUST_LOG` 环境变量控制日志输出：

```bash
# 默认 info 级别
RUST_LOG=info coauth server

# 调试级别（输出更多细节）
RUST_LOG=debug coauth server

# 仅显示特定模块的日志
RUST_LOG=coauth_handlers=debug,coauth_cli=info coauth server
```
