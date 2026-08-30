# 安装部署概述

coauth 是 Arkret Auth Server，负责用户认证、OAuth/OIDC、账号会话和 Arkret
session grant。

## 部署架构

一个典型的部署涉及两个主要域名：

1. **`auth.example.com`** — coauth 认证服务的对外地址
2. **`soland.example.com`** — Soland Station 的对外地址

所有域名都应通过反向代理（如 nginx）提供 HTTPS 访问。

## 部署流程

1. [安装](./installation.md) coauth 二进制文件或 Docker 镜像
2. 配置 [基本设置](./general.md)（生成配置文件、设置密钥等）
3. 设置 [PostgreSQL 数据库](./database.md)
4. 配置 [Station](./station.md)（例如 Soland）
5. 配置 [反向代理](./reverse-proxy.md) 将请求路由到正确的服务
6. （可选）配置[上游 SSO 提供商](./sso.md)（如 Google、GitHub 等）
7. [启动服务](./running.md)

## 系统要求

- **PostgreSQL** 13 或更高版本
- **Soland** Station（按部署需要）
- 反向代理（nginx、Caddy 等）用于 TLS 终止
- Linux x86_64 或 aarch64（预编译二进制）；其他平台需从源码编译
