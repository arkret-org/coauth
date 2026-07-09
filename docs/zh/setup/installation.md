# 安装

## 使用预编译二进制文件

我们为 Linux 提供预编译的二进制文件（支持 x86_64 和 aarch64 架构）。

### x86_64 (amd64)

```bash
curl -sL https://github.com/arkret/coauth/releases/latest/download/coauth-x86_64-linux.tar.gz | tar xz
```

### aarch64 (arm64)

```bash
curl -sL https://github.com/arkret/coauth/releases/latest/download/coauth-aarch64-linux.tar.gz | tar xz
```

解压后会得到 `coauth` 可执行文件。建议将其移动到 `/usr/local/bin/` 或其他在 `PATH` 中的目录。

## 使用 Docker

Docker 镜像发布在 GitHub Container Registry：

```bash
docker pull ghcr.io/arkret/coauth:latest
```

运行容器：

```bash
docker run -v $(pwd)/config.yaml:/config.yaml ghcr.io/arkret/coauth:latest \
  server -c /config.yaml
```

## 从源码编译

### 前置条件

- Rust 工具链（建议使用 [rustup](https://rustup.rs/) 安装）
- Node.js 和 npm（用于编译前端资源）
- PostgreSQL 客户端库

### 编译步骤

```bash
git clone https://github.com/arkret/coauth.git
cd coauth

# 编译前端资源
cd frontend
npm ci
npm run build
cd ..

# 编译 Rust 项目
cargo build --release
```

编译完成后，可执行文件位于 `target/release/coauth`。
