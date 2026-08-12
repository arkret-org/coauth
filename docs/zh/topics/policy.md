# 策略引擎

coauth 内置了一个可扩展的策略引擎，用于控制用户注册、客户端注册和授权请求等行为。策略提供者抽象层预留了多后端能力，当前随发行物提供的后端只有 Cedar。

## 支持的后端

| 后端 | 策略语言 | 性能 | 灵活性 | 特性标志 |
|------|---------|------|--------|---------|
| **Cedar**（默认） | Cedar | 极高（原生 Rust） | 中 | `cedar` |

## 工作原理

策略引擎基于两个核心 Trait 构建：

- **`PolicyProviderFactory`**：创建策略评估实例，管理动态数据更新
- **`PolicyEvaluator`**：执行具体的策略评估（注册、邮箱、授权等）

`PolicyFactory` 和 `Policy` 是面向外部的公共类型，内部通过 Trait 对象委托给选定的后端实现。

## Cedar 后端（默认）

[Amazon Cedar](https://www.cedarpolicy.com/) 是一种专为权限控制设计的策略语言。由于 Cedar 本身使用 Rust 编写，在 coauth 中集成的性能最高，无需 WebAssembly 开销。

Cedar 适用于以下场景：
- 希望使用简单、可读性好的策略语言
- 偏好纯声明式的授权方式

### 配置

```yaml
policy:
  engine: cedar
  cedar_policy_file: ./policies/policies.cedar
```

### 编写 Cedar 策略

Cedar 以 `(principal, action, resource, context)` 的形式评估授权请求。coauth 的映射关系：

- **Principal**（主体）：`Requester::"anonymous"`
- **Action**（操作）：`Action::"register"`、`Action::"add_email"`、`Action::"register_client"`、`Action::"authorize"`
- **Resource**（资源）：`Resource::"default"`
- **Context**（上下文）：评估输入数据（用户名、邮箱、客户端元数据等）

示例策略：

```cedar
// 默认允许所有注册（Cedar 默认拒绝）
permit(
    principal,
    action == Action::"register",
    resource
);

// 禁止用户名少于 3 个字符
forbid(
    principal,
    action == Action::"register",
    resource
) when {
    context.username.size() < 3
};

// 允许所有邮箱添加
permit(
    principal,
    action == Action::"add_email",
    resource
);

// 允许所有客户端注册
permit(
    principal,
    action == Action::"register_client",
    resource
);

// 允许所有授权请求
permit(
    principal,
    action == Action::"authorize",
    resource
);
```

## 自定义后端

你可以通过实现 `coauth-policy` 中的 `PolicyProviderFactory` 和 `PolicyEvaluator` Trait 来创建自定义策略后端，然后通过 `PolicyFactory::from_provider()` 注入到系统中。

## 策略评估点

策略引擎在以下场景被调用：

| 评估点 | 说明 |
|--------|------|
| 用户注册 | 控制是否允许新用户注册，可以验证用户名、邮箱等属性 |
| 邮箱添加 | 控制用户是否可以添加特定邮箱地址 |
| 客户端注册 | 控制 OAuth 客户端动态注册 |
| 授权请求 | 控制是否授予特定的 OAuth 作用域 |

策略仅在面向用户的上下文中评估，管理上下文不受策略限制。如需绕过策略限制，可以使用管理 API 或 CLI。

## 策略数据

可以通过配置文件或管理 API 向策略引擎传递数据。这些数据可在策略规则中引用：

```yaml
policy:
  data:
    admin_clients:
      - "client_id_1"
    allowed_domains:
      - "example.com"
```

在 OPA Rego 策略中使用：

```rego
package register

violation contains {"msg": "email domain not allowed"} if {
    email := input.registration_request.email
    domain := split(email, "@")[1]
    not domain in data.allowed_domains
}
```
