# sqli-scanner 部署指南

覆盖：环境要求、开发模式、生产部署（裸机 / Docker）、Tauri 桌面构建、环境变量全集、安全基线。常见报错排查见 [faq.md](./faq.md)。

---

## 一、环境要求

| 组件 | 版本要求 | 说明 |
|------|------|------|
| Node.js | **≥ 20** | 根目录与 `server/package.json` 的 `engines.node` 均为 `>=20`；npm 无额外版本约束（随 Node 20+ 自带即可） |
| npm | 随 Node 20+ | 需支持 `npm ci`（lockfile 安装） |
| Rust 工具链 | 仅桌面版需要 | Tauri 壳编译（Windows 需 MSVC 目标 + WebView2 运行时） |
| Docker / Docker Compose | 可选 | 一键容器部署（镜像基于 `node:24-alpine`） |
| Python 3 + sqlmap | 可选 | 仅 sqlmap 高级模式需要（见 [faq.md §二](./faq.md)） |

安装依赖（根目录前端 + server 引擎是两份独立 package）：

```bash
npm install
cd server && npm install && cd ..
```

---

## 二、开发模式

```bash
# 终端 A：检测引擎（Express，默认监听 127.0.0.1:4567）
npm run server

# 终端 B：前端 Vite 开发服（:5173，/api 代理到 4567，见 vite.config.ts）
npm run dev
```

浏览器打开 `http://localhost:5173`。引擎支持热重载开发：`cd server && npm run dev`（`node --watch`）。

环境变量用 `.env` 管理：`cp .env.example .env` 后按需修改（变量表见 [§五](#五环境变量全集)）。

---

## 三、生产部署

### 3.1 裸机（Node 直跑）

```bash
# 1. 构建前端（tsc --noEmit 类型检查 + vite build，产物 dist/）
npm run build

# 2. 启动引擎
HOST=127.0.0.1 PORT=4567 SCAN_API_TOKEN=<强随机串> \
ALLOWED_ORIGINS=https://scanner.example.com \
node server/index.js

# 3. 托管前端静态产物（任选其一）
#   a) vite preview（与官方 Dockerfile 同款）
npx vite --port 5173 --host 0.0.0.0 --preview dist
#   b) nginx：root 指向 dist/，并把 /api 反代到 127.0.0.1:4567
```

nginx 反代示例（前端与 API 同源，无需跨域）：

```nginx
server {
  listen 443 ssl;
  server_name scanner.example.com;

  root /var/www/sqli-scanner/dist;
  location / { try_files $uri /index.html; }   # SPA 回退
  location /api/ {
    proxy_pass http://127.0.0.1:4567;
    proxy_buffering off;        # SSE 实时进度流需要禁用缓冲
    proxy_read_timeout 3600s;   # 长扫描会话
  }
}
```

> 生产请置于 TLS 反代之后，并为引擎设置 `SCAN_API_TOKEN`（见 [§六](#六安全基线)）。

### 3.2 Docker Compose（推荐）

```bash
docker compose up -d
# 前端 http://localhost:5173   API http://localhost:4567
```

镜像内含：引擎（`node /app/server/index.js`）+ 前端产物（`vite preview` 托管 dist），tini 作 PID1，任一进程崩溃容器即退出（配合 `restart: unless-stopped` 自愈）。内置健康检查 `curl -f http://127.0.0.1:4567/api/health`。会话续跑数据持久化在卷 `sqli-sessions`（`/app/server/sessions`）。

容器默认 `HOST=0.0.0.0`（对外服务），修改配置直接编辑 `docker-compose.yml` 的 `environment` 段。

### 3.3 会话/日志落点

| 内容 | 位置 |
|------|------|
| 运行日志 | `server/logs/`（winston；URL 凭据已打码） |
| 会话文件（续跑） | 工作目录（如 `sqli-session-latest.json`）/ 系统临时目录；容器内为 `/app/server/sessions` 卷 |
| 前端历史记录 | 浏览器 localStorage（最多 100 条，凭据脱敏） |

---

## 四、Tauri 桌面版构建

### 4.1 `npm run build:engine` 的作用

把 `server/` 打成**可部署的 Node 运行时包**（脚本 `scripts/build-engine.mjs`），产物在 `server/dist-engine/`：

| 产物 | 说明 |
|------|------|
| `engine.mjs` | esbuild 打包的单文件 ESM 入口（bundle + 默认压缩，`--no-minify` 关闭） |
| `node_modules/sql.js/` | sql.js 运行时原样复制（入口 js + `sql-wasm.wasm` + package.json）——wasm 不能内联进单文件，否则 `__dirname` 失效导致加载失败 |

流程：esbuild bundle（sql.js 外部化）→ 复制 sql.js → 冒烟校验（import 产物验证 `default`/`start` 导出）→ 暂存到 `src-tauri/binaries/sqli-engine-assets/`（`--skip-binaries` 跳过）。

产物可独立运行：`cd server && node dist-engine/engine.mjs`（默认监听 `127.0.0.1:4567`，`PORT`/`HOST` 可覆盖）。

### 4.2 构建桌面壳

```bash
npm run build:engine   # 引擎运行时包 → src-tauri/binaries/
npm run tauri dev      # 开发调试
npm run tauri build    # 发布安装包
```

要点：

- `tauri.conf.json` 声明 `externalBin: binaries/sqli-engine`，sidecar 命名须为 `sqli-engine-<target-triple>[.exe]`（如 `sqli-engine-x86_64-pc-windows-msvc.exe`）。`build:engine` 暂存的是「Node 运行时包」（engine.mjs + sql.js），**单文件可执行**需再走 pkg/SEA 路线（脚本头部注释与 `report.md` 任务 2 记录了取舍：推荐 `@yao-pkg/pkg` 打 `engine.mjs`，Node SEA 需 CJS 入口且要内联 wasm，复杂度高）。
- 前端 API 地址：Web 版经 Vite 代理走 `/api`（`.env.development`）；桌面版需直连本机引擎，仓库根备有 `.env.tauri`（`VITE_API_BASE=http://127.0.0.1:4567`），构建时按 Vite mode 加载（`npx vite build --mode tauri`，`src/shared/apiClient.ts` 读取该值，缺省回落 `/api`）。
- `src-tauri/binaries/` 已被 .gitignore 忽略，产物不入库。
- Windows 构建需 Rust MSVC 工具链与 WebView2 运行时。

---

## 五、环境变量全集

`.env.example` 基础项 + 代码中实际消费的其他变量（按用途分组）：

### 基础（.env.example）

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `VITE_API_BASE` | `/api` | 前端 API 基础路径（开发经 Vite 代理；Tauri 版注入 `http://127.0.0.1:4567` 直连） |
| `HOST` | `127.0.0.1` | 引擎监听地址。生产对外部署设 `0.0.0.0`（**同时必须**配 `SCAN_API_TOKEN` + `ALLOWED_ORIGINS`）。注意：非回环 HOST 会自动启用 SSRF 严格层 |
| `PORT` | `4567` | 引擎监听端口 |
| `SCAN_API_TOKEN` | 空（不认证） | API Token。设置后报告/导出/SSE/所有 POST 均需携带（`x-api-token` 或 `Authorization: Bearer`），仅 5 个只读元数据端点豁免 |
| `ALLOWED_ORIGINS` | `http://localhost:5173,http://127.0.0.1:5173,http://localhost:4567,http://127.0.0.1:4567` | CORS 白名单（逗号分隔），需包含前端实际访问源；`.env.example` 示例值仅保留 5173 两项。无 `Origin` 头（curl / Tauri webview）默认放行 |
| `EXPLOIT_ENABLED` | `0` | `=1` 才开放 SQL Shell / 文件读写 / OS Shell 四个利用端点（默认关闭；测试环境见 `server/.env.test`） |

### 引擎行为

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `MAX_SCAN_API_CONCURRENT` | `8` | 并发扫描上限，超出返回 `ENGINE_BUSY (2002)` |
| `SQLMAP_PATH` | 无（回退 `server/tools/sqlmap/sqlmap.py`） | sqlmap 高级模式的 `sqlmap.py` 路径 |
| `PYTHON_PATH` / `SQLMAP_PYTHON` | `python3` | sqlmap 解释器（Windows 无 `python3` 命令时设 `PYTHON_PATH=python`） |

### SSRF 防护（httpClient）

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `SSRF_STRICT` | 自动（`HOST` 非 127.0.0.1/localhost 时视为开启） | 强严格：连回环/私网也拒绝 |
| `SSRF_ALLOW_PRIVATE` | 关 | `=1` 完全放行私网/回环（测试用） |
| `SSRF_ALLOW_CIDRS` | 空 | 逐段放行，如 `192.168.1.0/24,10.0.0.0/8`（优先级最高） |
| `SSRF_MAX_BODY_MB` | `5` | 请求/响应体积上限（MB） |

> 基础层（云元数据 169.254.169.254、链路本地、保留段）**无条件拒绝**，任何变量都放不开。

### OOB 接收端（oobReceiver）

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `OOB_LISTEN_HOST` | `127.0.0.1` | 接收端绑定地址（真实环境需对目标可达） |
| `OOB_RECEIVED_MAX` | `10000` | 已收 token 的 LRU 上限（防远程 flood） |
| `OOB_RATE_PER_MIN` | `60` | 按来源 IP 限速（req/min，防伪造命中） |
| `OOB_DNS_PORT` | `53` | DNS 通道监听端口（53 需 root/管理员） |
| `OOB_DNS_DOMAIN` | 空 | DNS 回调域名兜底（scan config 的 `oob.dnsDomain` 优先） |

---

## 六、安全基线

1. **默认仅本机**：引擎默认监听 `127.0.0.1`，不暴露网络。保持默认即最安全的使用方式（单人本机扫描）。
2. **Token 必开场景**：一旦 `HOST` 非 `127.0.0.1`（容器 / 局域网 / 公网），**必须**设置 `SCAN_API_TOKEN`（强随机串）+ `ALLOWED_ORIGINS`（仅前端实际源）。未设 token 时报告/导出/SSE 端点对任何可达者开放。
3. **`EXPLOIT_ENABLED=1` 是高危开关**：开放后即具备远程 SQL 执行 / 任意文件读写 / OS 命令执行能力（仍需前端授权勾选 + `authorized:true` 双门控）。仅在隔离环境、确有需要时开启，用完即关。
4. **SSRF 纵深**：引擎对出站目标做分层校验（云元数据永远拒绝；对外部署自动拒绝回环/私网，`SSRF_ALLOW_CIDRS` 按需最小化放行授权网段）。放行范围越大，引擎被滥用于内网横向的风险越高。
5. **传输安全**：跨网部署置于 TLS 反代之后；Token 不要走明文 HTTP。
6. **凭据保护**：日志对 URL/键值凭据打码；会话文件落盘前剥离 `auth`/`proxy` 配置；前端历史记录凭据脱敏。
7. **授权合规**：仅对已授权目标使用；拖库/利用等破坏性操作均有二次确认（详见 [user-guide.md §八](./user-guide.md)）。
