# 配置文件参考

本页列出 Pasion 配置文件的所有可用选项。完整的英文配置参考请查看[英文版本](../../reference/configuration.md)。

## 配置文件格式

Pasion 使用 YAML 格式的配置文件。通过 `-c` 或 `--config` 参数指定：

```bash
coauth server -c config.yaml
```

## 主要配置段

### `http` — HTTP 服务器

```yaml
http:
  # 对外公开的基础 URL（必须包含协议和域名）
  # 同时用于生成 upstream OAuth callback URL
  public_base: https://auth.example.com/

  # 可选的签发者 URL（用于 OIDC 发现）
  # issuer: https://auth.example.com/

  # 监听器配置
  listeners:
    - name: web
      binds:
        - address: "[::]:8080"
      proxy_protocol: false
      resources:
        - name: discovery    # OIDC 发现端点
        - name: human        # 用户界面（登录、注册等）
        - name: oauth        # OAuth 2.0 端点
        - name: compat       # 旧版 Matrix 登录兼容层
        - name: graphql      # GraphQL API
        - name: assets       # 静态资源
          path: /path/to/dist/
        - name: health       # 健康检查端点

  # 信任的代理 IP 范围
  trusted_proxies:
    - 192.168.0.0/16
    - 172.16.0.0/12
    - 10.0.0.0/8
    - 127.0.0.0/8
    - "::1/128"
```

### `database` — 数据库连接

```yaml
database:
  uri: postgresql://user:password@localhost/coauth
  max_connections: 10
  min_connections: 0
  connect_timeout: 30
```

### `matrix` — Matrix Homeserver

```yaml
matrix:
  homeserver: example.com          # Matrix 服务器名称
  secret: "共享密钥"                # 与 homeserver 的共享密钥
  endpoint: "https://matrix.example.com"  # homeserver API 地址
```

### `secrets` — 密钥和加密

```yaml
secrets:
  encryption: "32字节的加密密钥（Base64编码）"
  keys:
    - kid: "key-id-1"
      key: |
        -----BEGIN RSA PRIVATE KEY-----
        ...
        -----END RSA PRIVATE KEY-----
```

### `passwords` — 密码策略

```yaml
passwords:
  enabled: true              # 是否启用密码登录
  minimum_complexity: 3      # 最低密码复杂度（0-4）
  schemes:
    - version: 1
      algorithm: argon2id    # 密码哈希算法
```

### `account` — 账户管理

```yaml
account:
  password_registration_enabled: false
  login_with_email_allowed: false

  # 可选的管理员门户地址。
  # 配置后，具备管理员权限的用户会在账户页面看到入口链接。
  admin_portal_url: https://admin.example.com/
```

### `email` — 邮件发送

```yaml
email:
  from: '"Pasion" <noreply@example.com>'
  reply_to: '"Support" <support@example.com>'
  provider:
    type: resend
    api_key: "re_xxxxxxxxx"
    # 可选类型: blackhole / smtp / sendmail / resend / sendgrid / twilio / brevo / aws_ses / http_webhook
    # webhook:
    #   signing_secret: whsec_xxxxxxxxx
    #   max_age_seconds: 300

  # SMTP 示例
  # provider:
  #   type: smtp
  #   mode: starttls
  #   hostname: smtp.example.com
  #   port: 587
  #   username: "smtp_user"
  #   password: "smtp_password"

  # AWS SES 示例
  # provider:
  #   type: aws_ses
  #   region: us-east-1
  #   access_key_id: AKIAXXXXXXXXXXXXXXXX
  #   secret_access_key: your-secret-access-key
  #   session_token: optional-session-token
  #   endpoint: https://email.us-east-1.amazonaws.com
  #   configuration_set_name: default-set
  #   webhook:
  #     topic_arn: arn:aws:sns:us-east-1:123456789012:ses-feedback
  #     auto_confirm_subscription: true
```

`twilio` 邮件 provider 实际上走的是 Twilio SendGrid 的 Mail Send API，
和短信里的 `twilio` provider 是两套能力。

如果启用了异步投递回执，可以把公开 webhook 路径配置到对应 provider：
`/webhooks/email/resend`、`/webhooks/email/sendgrid`、`/webhooks/email/twilio`、
`/webhooks/email/brevo`、`/webhooks/email/aws-ses`。

### `sms` — 短信发送

```yaml
sms:
  # 默认 provider：不发送任何短信
  provider:
    type: blackhole

  # Twilio 短信
  #provider:
  #  type: twilio
  #  account_sid: ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
  #  auth_token: your-auth-token
  #  from_number: +12065550123

  # HTTP webhook 短信
  #provider:
  #  type: http_webhook
  #  url: https://sms.example.com/api/send
  #  api_key: example-token
  #  from_number: +12065550123

  # 阿里云短信
  #provider:
  #  type: aliyun_sms
  #  access_key_id: your-access-key-id
  #  access_key_secret: your-access-key-secret
  #  sign_name: 你的签名
  #  template_code: SMS_123456789

  # 腾讯云短信
  #provider:
  #  type: tencent_cloud_sms
  #  secret_id: your-secret-id
  #  secret_key: your-secret-key
  #  sdk_app_id: "1400000000"
  #  sign_name: 你的签名
  #  template_id: "1234567"

  # Paloud internal notification API
  #provider:
  #  type: paloud_internal
  #  url: https://admin.example.com/api/v1/internal/notifications/sms/send
  #  key_id: coauth-service
  #  secret: super-secret
  #  workspace: demo
```

`sms.provider.type` 支持 `blackhole`、`twilio`、`http_webhook`、
`aliyun_sms`、`tencent_cloud_sms` 和 `paloud_internal`。

### `telemetry` — 可观测性

```yaml
telemetry:
  tracing:
    exporter: otlp           # none / stdout / otlp
    endpoint: "https://otel-collector:4318"
    propagators:
      - tracecontext
      - baggage
  metrics:
    exporter: prometheus      # none / stdout / otlp / prometheus
```

### `rate_limiting` — 速率限制

```yaml
rate_limiting:
  login:
    burst: 3                  # 突发允许次数
    per_second: 0.5           # 每秒允许次数
  registration:
    burst: 3
    per_second: 0.1
```

### `captcha` — 验证码

```yaml
captcha:
  service: recaptcha_v2       # recaptcha_v2 / cloudflare_turnstile / hcaptcha
  site_key: "你的站点密钥"
  secret_key: "你的密钥"
```

### `policy` — 策略引擎

Pasion 支持多种策略引擎后端。详细文档请参阅[策略引擎](../topics/policy.md)。

#### Cedar 后端（默认）

```yaml
policy:
  engine: cedar  # 默认值，可省略
  cedar_policy_file: ./policies/policies.cedar
```

#### Remote HTTP 后端

需要编译时启用 `remote` 特性标志。

```yaml
policy:
  engine: remote
  remote_endpoint: http://localhost:8181
```

更多配置选项请参阅[完整英文参考文档](../../en/reference/configuration.md)。
