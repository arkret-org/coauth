# About this documentation

This documentation describes `coauth`, the Contrix Auth / Account Server. It is
intended for operators, administrators, and developers integrating coauth with
Contrix Principal Servers, public DID resolver services, `sodmin`, and first-party clients.

`coauth` is an OAuth and OpenID Connect provider. Its primary product
surface is Contrix-native account, session, DID-binding, claim, and admin
integration.

The documentation itself is built using [mdBook](https://rust-lang.github.io/mdBook/).

## How the documentation is organized

This documentation has four main sections:

- The [installation guide](./setup/) explains how to run `coauth` on your own
  infrastructure.
- The topics section covers service behavior such as the [policy engine](./topics/policy.md),
  [authorization sessions](./topics/authorization.md), and access tokens.
- The reference documentation covers [configuration options](./reference/configuration.md),
  the [Admin API](../api/index.html), [OAuth scopes](./reference/scopes.md),
  and the [command line interface](./reference/cli/).
- The developer documentation is intended for people contributing to the
  project.

## Language / 语言

- [English](./README.md) (current)
- [中文 (Chinese)](../zh/README.md)
