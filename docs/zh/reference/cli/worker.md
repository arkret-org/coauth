# `worker`

以独立进程运行后台任务 Worker。

## 用法

```bash
coauth worker -c config.yaml
```

## Worker 的职责

Worker 处理以下异步任务：

- **发送邮件** — 验证码、密码重置链接、通知邮件
- **Homeserver 通知** — 用户创建或停用时同步到 Matrix homeserver
- **会话清理** — 根据配置的 TTL 过期旧会话和令牌
- **定时维护** — 刷新活动追踪数据等定期任务

## 何时单独运行 Worker

默认情况下，`coauth server` 会在同一进程中运行 Worker。以下场景适合单独运行：

- **水平扩展** — 多个 HTTP 服务器实例但只需一个 Worker
- **资源隔离** — 后台任务不应与 HTTP 请求处理竞争资源
- **分布式部署** — HTTP 服务器和 Worker 运行在不同节点上
