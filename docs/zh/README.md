# 关于本文档

本文档介绍 `coauth`，即 Contrix Auth / Account Server。它面向运维人员、管理员，以及
需要把 coauth 接入 Contrix Principal Server、public DID resolver 服务、`sodmin` 和第一方客户端的开发者。

`coauth` 是 OAuth 2.0 和 OpenID Connect Provider。它的主产品接口是 Contrix-native
账户、会话、DID 绑定、claim 和 admin 集成。Legacy Matrix / Palpo 只作为旧部署的
adapter 路径记录。

本文档使用 [mdBook](https://rust-lang.github.io/mdBook/) 构建。

## 文档结构

本文档分为四个主要部分：

- [安装部署指南](./setup/) 介绍如何在自己的基础设施上运行 `coauth`。
- 专题部分介绍服务行为，包括[策略引擎](./topics/policy.md)、[授权会话](./topics/authorization.md)、
  access token 和 legacy compatibility。
- 参考文档涵盖[配置选项](./reference/configuration.md)、[管理 API](../api/index.html)、
  [OAuth 2.0 scope](./reference/scopes.md) 和[命令行工具](./reference/cli/)。
- 开发文档面向希望参与项目贡献的开发者。

## 语言 / Language

- [English](../en/README.md)
- [中文](./README.md)（本页）
