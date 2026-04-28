# 贡献指南

感谢你对 Pasion 项目的贡献兴趣！

## 开发环境

### 前置条件

- Rust 稳定版工具链（通过 [rustup](https://rustup.rs/) 安装）
- Node.js 20+ 和 npm（用于前端开发）
- PostgreSQL 13+（用于运行测试）
- [Open Policy Agent](https://www.openpolicyagent.org/docs/latest/#1-download-opa)（用于编译策略）

### 克隆和构建

```bash
git clone https://github.com/taidge/coauth.git
cd coauth

# 编译前端资源
cd frontend
npm ci
npm run build
cd ..

# 编译所有 Rust crate
cargo build
```

### 运行测试

```bash
# 运行单元测试
cargo test

# 运行需要数据库的集成测试
export DATABASE_URL="postgresql://coauth:password@localhost/coauth_test"
cargo test --workspace
```

## 代码规范

### 更新生成文件

仓库根目录下可以使用以下脚本更新自动生成的文件：

```bash
# macOS / Linux
sh ./misc/update.sh

# Windows
pwsh -File ./misc/update.ps1
```

### 格式化

```bash
# Rust 代码格式化
cargo fmt

# 前端代码格式化
cd frontend && npm run lint
```

### 代码检查

```bash
# Rust lint
cargo clippy --workspace --all-targets
```

## 提交 Pull Request

1. 从 `main` 分支创建你的功能分支
2. 编写代码并添加测试
3. 确保所有测试通过：`cargo test`
4. 确保代码格式正确：`cargo fmt --check`
5. 确保没有 lint 警告：`cargo clippy`
6. 提交 PR 并描述你的更改

### PR 标签

PR 使用标签来自动生成变更日志：

- `A-Feature` — 新功能
- `A-Bugfix` — Bug 修复
- `A-Docs` — 文档更新
- `A-Internal` — 内部重构
- `A-Dependencies` — 依赖更新

## 项目结构

参见[架构设计](./architecture.md)了解代码库的组织方式。
