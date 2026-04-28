# 关于 Application Services 登录

加密的 Application Services/Bridges 目前使用 `m.login.application_service` 登录类型来为用户创建设备。此 API 在 Pasion 中**不可用**。

## 影响

这意味着**加密桥接器（encrypted bridges）无法与 Pasion 配合使用**。

## 解决方法

- **在桥接器中禁用端到端加密** — 如果你的桥接器不需要端到端加密，将其配置为跳过设备创建和密钥管理
- **使用非加密房间** — 桥接器仍然可以在非加密房间中正常工作

## 背景

在使用 Pasion 的原生 OIDC 部署中，认证完全通过 OAuth 2.0 流程处理，不支持旧版 Matrix 登录 API 中的 Application Service 登录方式。

## 未来计划

Matrix 规范正在开发原生 OIDC 环境下的 Application Service 设备管理标准机制。一旦该标准确定，Pasion 将会实现支持。
