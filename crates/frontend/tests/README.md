# 前端浏览器回归

在Coauth根目录先构建当前源码，再从同一构建目录启动SPA：

```sh
python scripts/build-frontend.py --out-dir artifacts/frontend-checks/web
python scripts/serve-frontend.py --assets-dir artifacts/frontend-checks/web --port 4183
```

另一个进程执行官方入口：

```sh
npm ci --prefix crates/frontend
COAUTH_TEST_URL=http://127.0.0.1:4183 COAUTH_BROWSER_CHANNEL=chromium npm test --prefix crates/frontend
```

Windows本机验证前在同一PowerShell调用工作区的`arkret-work/tools/use-d-drive-cache.ps1`，缓存和TEMP全部在D盘，环境变量使用PowerShell语法；已有Edge可用时设置`COAUTH_BROWSER_CHANNEL=msedge`。构建目录必须是本轮新输出，不能复用旧bundle。

`npm test`按顺序运行`run.cjs`、`design.cjs`、`preferences.cjs`，任一失败立即返回非零。它们共用当前fixtures，分别覆盖账户页面流程、Passkey撤销确认/失败/明暗语言，以及语言切换与草稿保护。`COAUTH_TEST_ARTIFACTS`可指定结果和截图目录。

发布工作流的`release-frontend`任务在上传刚构建的frontend artifact前运行同一入口，不重复构建或另启后端。API被fixtures拦截，这些检查验证实际WASM页面，不代表真实账户/数据库业务验收。`smoke.cjs`、`visual.cjs`是另行选用的截图/视觉工具，不包含在此默认行为验收中。
