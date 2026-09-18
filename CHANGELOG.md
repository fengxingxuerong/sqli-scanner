# Changelog

本项目版本号遵循 [语义化版本 2.0.0](https://semver.org/lang/zh-CN/)。

## [1.1.0] - 2026-09-18

### 安全加固（破坏性变更，请务必阅读「升级注意」）

- **默认鉴权（fail-closed）**：引擎新增统一 token 解析 `resolveApiToken()`。
  - 优先级：`SCAN_API_TOKEN_FILE`（Docker/K8s secret）→ `SCAN_API_TOKEN` → 回环监听允许无鉴权。
  - **监听非回环地址（含容器必需的 `HOST=0.0.0.0`）且未配置 token 时，引擎拒绝启动**并打印修复指引；
    确知风险可用 `SCAN_API_ALLOW_NO_TOKEN=1` 显式放行（启动打显著告警）。
  - `docker-compose.yml` 的 `SCAN_API_TOKEN` 改为必填（`${VAR:?}`），未设置时 compose 直接报错。
- **CSP 修复（影响 Docker 单端口部署）**：安全响应头按响应类型分流——
  `/api`、`/sqlmap` 仍为 `default-src 'none'`；前端静态资源改为放行 `'self'`（含 MUI 所需的
  `style-src 'unsafe-inline'`）。修复前 Docker/单端口部署打开即白屏（本地 Vite 与桌面端不受影响，
  故开发期难以发现）。
- **桌面端（Tauri）引擎连接加固**：
  - sidecar 端口不再写死 4567——被占用时自动改用空闲端口；
  - 引擎生成一次性 token（`crypto.randomBytes(32)`）经 stdout `ENGINE_TOKEN=` 回传，
    壳通过 `get_engine_info` 命令交给前端自动注入，本机其它进程无法再直连该引擎；
  - sidecar 缺失/启动失败不再 panic，改为广播 `engine-exit` + 前端「重启引擎」入口；
  - 引擎默认 `ALLOWED_ORIGINS` 增加 `http://tauri.localhost`、`tauri://localhost`。
- **静态外壳与 API 鉴权分离**：启用 `SCAN_API_TOKEN` 后，前端外壳（dist 静态资源与 SPA 路由）不再被
  token 中间件拦截（此前 `GET /` 直接返回 401 JSON，Docker/单端口部署下 **Web UI 完全打不开**）；
  所有数据接口（含不带 `/api` 前缀的 `/scan/*`、`/exploit/*`、`/sqlmap/*`）仍需 token。
- **桌面端 sidecar 可打包了**（此前无法构建）：
  - `npm run build:sidecar`（`scripts/build-sidecar.mjs`）走 Node SEA 路线：
    cjs bundle → SEA blob → postject 注入 → 冒烟（起 exe 断言 `/api/health`=200 与
    `ENGINE_TOKEN` 回传）。产物 `src-tauri/binaries/sqli-engine-<target-triple>[.exe]`（Windows x64 约 86 MB）。
  - 为什么不用 pkg：本机实测 `@yao-pkg/pkg --target node20-win-x64` 无预编译 base binary，
    退化为源码编译 Node 并因缺 NASM 失败。
  - 修复 `--format cjs` 产物不可运行：CJS 下 esbuild 不提供 `import.meta.url`，
    引擎入口定位前端产物时抛 `ERR_INVALID_ARG_TYPE`（此前该格式从未被验证过）。
  - 修复 `tauri.conf.json` 缺 `bundle.externalBin`：即使产出了 exe，`tauri build` 也不会打进安装包，
    运行时 `shell().sidecar("sqli-engine")` 找不到可执行文件。
  - `build:tauri` / `package:win` / `package:mac` 三条链已补上 sidecar 构建步骤。
  - **实测打包结果**：`npx tauri build --bundles nsis` 成功产出
    `SQL注入检测工具_1.1.0_x64-setup.exe`（26.4 MB，内含 90 MB sidecar 的 LZMA 压缩）；
    产物结构验证：`target/release/sqli-scanner.exe`（壳）+ `sqli-engine.exe`（sidecar）同目录，
    启动后日志 `[引擎] sidecar 已启动：127.0.0.1:4567`，`sqli-engine.exe` 进程在线。
  - ⚠️ **MSI（WiX）在当前用户目录下会失败**：`light.exe` 无法处理含全角括号的路径
    （`C:\Users\Admin（无密码）\AppData\...`）。因此 `package:win` 默认改用 NSIS；
    需要 MSI 时请在纯 ASCII 路径下构建。
  - **桌面版「直连 SQLite」已可用（B1，全内联方案）**：此前 sql.js 在 bundle 中为 external，
    SEA 单文件不含它，桌面直连 SQLite 会**静默回退**到内存自检驱动（扫得出结果但不是真库）。
    现改为**全内联**：
    - `scripts/build-engine.mjs` 新增 `--inline-sqljs`：sql-wasm.js 打进 bundle（不再 external）；
    - `sql-wasm.wasm` 作为 **SEA asset** 内嵌（`sea-config.json` 的 `assets`）；
    - 新增 `server/src/core/sqlJsLoader.js` 统一三种形态下的定位：SEA 用
      `require('node:sea').getAsset()` 取出 wasm 后经 `initSqlJs({ wasmBinary })` 直喂
      ——sql.js 一收到 `wasmBinary` 就跳过 `__dirname + readFileSync`，因此**零外部文件**。
    - 构建期硬断言：SEA asset 键名与 `sqlJsLoader.js` 的 `SQL_WASM_ASSET` 必须一致，
      且 `tauri.conf.json` 不得声明 sql.js 相关 `bundle.resources`（防两套依赖不同步）。
    - 冒烟升级：exe 在**全新空目录**下运行（旧版用 `cwd=dist-engine` 掩盖了外部依赖），
      并真跑一次直连 SQLite 扫描、按 SSE 事件断言 `detection_found ≥ 1`，
      同时检查引擎日志无「回退到内存自检驱动」告警 —— 负向验证：未内联版本该断言确实报 FAIL。
    - 为什么绕这么一圈：SEA 的 `require` 被劫持为「只认内建模块」，`require('sql.js')` 抛
      `No such built-in module: sql.js`，`NODE_PATH` 同样无效（实测四种方案对照）。
- **sqlmap `--eval` 默认禁用（A4）**：该参数会让 sqlmap 在服务端执行 **Python 表达式**（等价代码执行）。
  旧实现只打一条 warn 就透传；`POST /api/sqlmap/start` 的 body 是原样透传的，因此无鉴权部署下
  任何可达客户端都能提交表达式。现改为**双条件门控**：`SQLMAP_ALLOW_EVAL=1` **且**引擎已启用
  API 鉴权（`SCAN_API_TOKEN`）；不满足直接拒绝并给出启用条件（不静默丢弃参数）。
- **会话落盘注入点原始值加密（A5）**：`sessions/*.json` 的 `points[].originalValue` 在注入点为
  Cookie / 自定义认证头时等同于会话凭据，而 compose 还把 sessions 目录挂在 named volume 上。
  现**写盘封存（AES-256-GCM，`enc:v1:` 前缀）+ 读盘解封**，内存保持明文 ⇒ 断点续跑语义不变。
  密钥来源：`SCAN_SESSION_KEY` → 由 `SCAN_API_TOKEN` 派生 → 进程随机兜底；
  解不开的场景（换 key / 旧随机 key）把该点降级为「待重扫」，不会把密文当参数值发出去。
- **CI 门禁加固**：Docker 冒烟增加「无 token 必须 401」「静态资源 CSP 必须含 'self'」两条断言。
- **Rust 门禁可在本地复现（B4）**：
  - 新增 `src-tauri/rust-toolchain.toml` **单点锁定**工具链版本（`1.98.0` + `rustfmt`/`clippy`）。
    此前 CI 用 `dtolnay/rust-toolchain@stable` 会滚动到最新 stable，而 rustfmt 的换行/宏排版
    在小版本间会变、clippy 也会新增 lint → 会出现「本机格式化通过、CI 报 fmt 失败」这类
    不可复现的红。CI 同步改为 `@master` + `toolchain: 1.98.0`，两边完全同版本。
  - 修复 `src-tauri/src/lib.rs` 两处 `cargo fmt --check` 违规（纯排版：`.env(...)` 多行化、
    `invoke_handler!` 宏参数换行），均为 A3 加固时引入、此前**无任何门禁覆盖**。
  - 新增 npm scripts：`lint:rust`（fmt --check + clippy -D warnings）、`fmt:rust`、
    **`check:all`**（ESLint + 前后端 tsc + 架构门禁 + Rust 门禁，一条命令复现 CI 主门禁）。
  - 门禁灵敏度已实测：故意插入 `x == x` 会被 clippy 判 `error: equal expressions as operands`
    （退出码 101），证明「0 warning」不是空跑。
- **新增发布冒烟 `e2e/diag/release-smoke.mjs`**（已接入 CI 的 `release-smoke` job）：在临时沙箱里以
  **生产配置**（token + 托管 dist + 引擎常驻）跑完整链路——鉴权、跨站、CSP 分流、静态资源可达、
  真靶场扫描（API 与 CLI 两条路径）、五种报告交付物与退出码语义，共 30 项断言。

### 修复

- 报告导出确定性：`POC_CACHE` 由 WeakMap（键＝对象引用）改为稳定字符串键 + 容量上限，
  修复「同一份报告多次导出逐字节一致」偶发失败（实测修复前 3 次挂 1 次，修复后 5 次全过）。
- 拖库行切分（MySQL 系）：`GROUP_CONCAT` 显式行分隔符、分页下推进子查询、
  `CONCAT_WS` 的 NULL 安全包装，修复「多行落成 1 行且跨行串列」。
  - 真库实测：MySQL 8.0.28 的 `SEPARATOR` 只接受字面量（`SEPARATOR CHAR(30)` 为 1064 语法错误），
    改用 `0x1E`/`0x0A`；聚合结果的 `LIMIT/OFFSET` 对聚合输出无意义，已下推到源表行。
- 网络失败不再被判负：新增 `isNetworkFailureError()` 与 `addNetworkErrorPoint()`，
  注入点全部检测器因传输层失败时标记为未决（报告 `reliable=false`），不再写成「已检测、无漏洞」。
- 本地/私网目标默认绕过环境变量代理（`proxyBypassLocal`，默认开），
  修复装了系统代理时本地靶场扫描出现假阴性。
- ESLint 全量 31 处未使用导入/变量清理（大文件拆分遗留），并修复 `e2e/blackbox-lab/lab-app.mjs`
  中 `res` 未定义导致 WAF 拦截路径抛 `ReferenceError` 的缺陷。

### 依赖

- 服务端 `npm audit fix`：qs / body-parser 相关 3 项中危清零（当前 0 vulnerabilities）。

### 升级注意

1. **容器/非回环部署必须设置 `SCAN_API_TOKEN`**（或 `SCAN_API_TOKEN_FILE`），否则引擎起不来。
2. Web 端启用鉴权后需填写一次 token：首次 401 会弹出输入框（写入 `localStorage.scanApiToken`），
   或构建期注入 `VITE_SCAN_API_TOKEN`。
3. 桌面端升级后由应用自动注入端口与 token，无需手工配置；若从旧版升级，建议重新打包 sidecar。

## [1.0.0] - 2026-09-01

- 首个完整版本：Web / Docker / Tauri 桌面三端、CLI、9 类检测技术、拖库与利用能力、
  225 个 tamper 插件、报告导出（HTML/JSON/Markdown/SARIF/CSV）。
