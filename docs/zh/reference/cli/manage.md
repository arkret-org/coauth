# `manage`

用户和账户管理命令。

## 用户管理

### 注册用户

```bash
coauth manage register-user -c config.yaml <用户名>
```

### 设置密码

```bash
coauth manage set-password -c config.yaml <用户名>
```

### 添加邮箱

```bash
coauth manage add-email -c config.yaml <用户名> <邮箱>
```

## 管理员管理

### 提升为管理员

```bash
coauth manage promote-admin -c config.yaml <用户名>
```

### 撤销管理员权限

```bash
coauth manage demote-admin -c config.yaml <用户名>
```

### 列出所有管理员

```bash
coauth manage list-admin-users -c config.yaml
```

## 用户状态

### 锁定用户

```bash
coauth manage lock-user -c config.yaml <用户名>
```

### 解锁用户

```bash
coauth manage unlock-user -c config.yaml <用户名>
```

## 会话管理

### 终止用户的所有会话

```bash
coauth manage kill-sessions -c config.yaml <用户名>
```

## 令牌管理

### 签发注册令牌

生成一次性注册令牌：

```bash
coauth manage issue-user-registration-token -c config.yaml
```

## 批量操作

### 同步所有用户到 Principal Server

通过 Principal Server 抽象同步 coauth 中的所有用户：

```bash
coauth manage provision-all-users -c config.yaml
```
