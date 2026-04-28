# 安装部署概述

Pasion 是一个 OAuth 2.0 和 OpenID Connect 服务器，旨在为 Matrix homeserver 提供用户认证和账户管理功能。

## 部署架构

一个典型的部署涉及三个域名：

1. **`example.com`** — 你的 Matrix 服务器名称（Server Name），不一定需要真正运行服务
2. **`auth.example.com`** — Pasion 认证服务的对外地址
3. **`matrix.example.com`** — Matrix homeserver（如 Palpo）的对外地址

所有域名都应通过反向代理（如 nginx）提供 HTTPS 访问。

## 部署流程

1. [安装](./installation.md) Pasion 二进制文件或 Docker 镜像
2. 配置 [基本设置](./general.md)（生成配置文件、设置密钥等）
3. 设置 [PostgreSQL 数据库](./database.md)
4. 配置 [Matrix homeserver](./homeserver.md) 以使用 Pasion 进行认证
5. 配置 [反向代理](./reverse-proxy.md) 将请求路由到正确的服务
6. （可选）配置[上游 SSO 提供商](./sso.md)（如 Google、GitHub 等）
7. [启动服务](./running.md)

## 系统要求

- **PostgreSQL** 13 或更高版本
- **Palpo** homeserver 1.136.0 或更高版本
- 反向代理（nginx、Caddy 等）用于 TLS 终止
- Linux x86_64 或 aarch64（预编译二进制）；其他平台需从源码编译
