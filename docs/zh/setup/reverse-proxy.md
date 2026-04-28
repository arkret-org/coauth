# 配置反向代理

在生产环境中，Pasion 应部署在反向代理之后以提供 TLS 终止和请求路由。

## nginx 配置示例

以下示例假设：
- Pasion 监听在 `localhost:8080`
- Palpo (Matrix homeserver) 监听在 `localhost:8008`

```nginx
# 认证服务 - auth.example.com
server {
    listen 443 ssl http2;
    server_name auth.example.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://localhost:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

# Matrix homeserver - matrix.example.com
server {
    listen 443 ssl http2;
    server_name matrix.example.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://localhost:8008;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## 客户端 IP 保持

Pasion 支持两种方式获取真实的客户端 IP 地址：

### 方式一：X-Forwarded-For 头

这是最常见的方式。在 Pasion 配置中设置信任的代理 IP：

```yaml
http:
  trusted_proxies:
    - 127.0.0.0/8
    - ::1/128
```

### 方式二：PROXY 协议

如果你的负载均衡器支持 PROXY 协议（如 HAProxy），可以在 Pasion 的监听器中启用：

```yaml
http:
  listeners:
    - name: web
      binds:
        - address: "[::]:8080"
      proxy_protocol: true
      resources:
        - name: all
```

## 静态资源优化

建议让反向代理直接提供静态资源（CSS、JS、字体等），以减轻 Pasion 服务的负担：

```nginx
location /assets/ {
    alias /path/to/coauth/dist/;
    expires 1y;
    add_header Cache-Control "public, immutable";
}
```
