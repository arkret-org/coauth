# 关于本文档

本文档旨在从管理员和开发者两个角度，全面介绍 Pasion 的工作原理和使用方法。

Pasion 是一个面向 Matrix 的 OAuth 2.0 和 OpenID Connect 身份认证服务器。它的创建是为了支持 Matrix 向基于 OpenID Connect (OIDC) 的认证架构迁移，详见 [MSC3861](https://github.com/matrix-org/matrix-doc/pull/3861)。

本文档使用 [mdBook](https://rust-lang.github.io/mdBook/) 构建。在线版本请访问 <https://palpo-im.github.io/coauth/>。

## 文档结构

本文档分为四个主要部分：

- [安装部署指南](./setup/) 将引导你在自己的基础设施上部署 Pasion。
- 专题部分深入介绍服务的工作原理，包括[策略引擎](./topics/policy.md)和[授权会话](./topics/authorization.md)的管理方式。
- 参考文档涵盖[配置选项](./reference/configuration.md)、[管理 API](../api/index.html)、服务支持的[作用域](./reference/scopes.md)以及[命令行工具](./reference/cli/)。
- 开发文档面向希望[参与项目贡献](./development/contributing.md)的开发者。

## 语言 / Language

- [English](../en/README.md)
- [中文](./README.md)（本页）
