# SQL 注入检测工具（SQLi Scanner）

一份代码、双形态（Web 全栈 + Tauri 桌面壳）的 SQL 注入自动化检测工具。
前端用 React + MUI + Tailwind，检测引擎用 Node/Express，检测能力以**策略模式**组织，支持
**联合查询 / 报错 / 布尔盲注 / 时间盲注**四类注入检测，以及数据库指纹、列类型枚举与数据提取（拖库）。

> 仅用于**授权环境下的安全测试与学习**，禁止用于未授权目标。

---

## 架构概览

```
React 前端（Web / Tauri 共用）
        │  VITE_API_BASE 切换：Web=/api，Tauri=http://127.0.0.1:4567
        ▼
Express 引擎（:4567）  ── SSE 实时进度 ──▶ 前端 EventSource
        │
        ├─ ScanManager（门面：发现→指纹→检测→提取→报告）
        ├─ Detector×4（策略模式：Union / Error / Boolean / Time）
        ├─ DBFingerprinter / Extractor / ColumnTypeEnumerator
        └─ Scheduler（并发池 + 令牌桶限速 + 重试）
```

- **Web 版**：`npm run dev` 启动 Vite（:5173），`npm run server` 启动引擎（:4567），Vite 代理 `/api` → 引擎。
- **Tauri 版**：Rust 壳以 **sidecar** 拉起引擎进程（:4567），前端 `VITE_API_BASE` 指向 `http://127.0.0.1:4567`，业务代码零改动。

---

## 目录结构

```
sqli-scanner/
├── src/                # React 前端（shared/types、hooks、store、pages、components）
├── server/             # Node/Express 检测引擎（config/core/engine/services/api）
├── src-tauri/          # Tauri 桌面壳（sidecar 拉起引擎）
├── package.json        # 根脚本（dev/server/tauri/build）
└── vite.config.ts      # /api 代理到 :4567
```

---

## 快速开始

### 1. 安装依赖

```bash
# 前端依赖
npm install

# 引擎依赖
cd server && npm install && cd ..
```

### 2. 启动（Web 版）

```bash
# 终端 A：启动检测引擎
npm run server
# 或 cd server && node index.js

# 终端 B：启动前端
npm run dev
```

打开 http://localhost:5173 ，填入目标 URL 即可扫描。

### 3. 构建生产前端

```bash
npm run build      # 产物在 dist/，可由 Express 静态托管或与引擎同域部署
npm run preview
```

### 4. 桌面版（Tauri，可选）

```bash
# 先将 server/ 用 pkg/esbuild 打成单文件可执行放入 src-tauri/binaries/sqli-engine
npm run build:engine
# 启动桌面壳（需安装 Rust 工具链）
npm run tauri dev
```

---

## 默认参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| concurrency | 4 | 并发检测线程数 |
| timeoutMs | 10000 | 单请求超时（ms） |
| retry | 2 | 失败重试次数 |
| timeThresholdMs | 1500 | 时间盲注判定阈值（ms） |
| ratePerSec | 3 | 限速（请求/秒，令牌桶） |
| enableExtract | true | 拖库开关（UI 二次确认） |
| port | 4567 | 引擎监听端口 |

---

## API 端点（契约）

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/scan/start` | 启动扫描，返回 `{ scanId }` |
| GET | `/api/scan/:id` | 获取实时报告快照 |
| GET | `/api/scan/:id/events` | SSE 实时进度流 |
| POST | `/api/scan/:id/stop` | 停止扫描 |
| GET | `/api/scan/:id/report` | 获取完整报告 |
| GET | `/api/scan/:id/report/export?format=json\|html` | 导出报告 |
| GET | `/api/health` | 健康检查 |
| GET | `/api/payloads?dbms=&technique=` | 查看只读 Payload 模板 |

统一响应包：`{ "code": 0, "data": <任意>, "message": "ok" }`。

---

## 风险定级

- **Critical**：可完成数据提取（UNION 回显或盲注二分拖库成功）
- **High**：确认可回显注入（UNION / 报错）
- **Medium**：仅盲注确认但提取受限（布尔 / 时间）
- **Low**：单点疑似证据不足

---

## 技术栈

前端：React 18 · MUI 5 · Tailwind 3 · react-router-dom 6 · zustand 4 · axios · Vite 5 · TypeScript 5
引擎：Node.js · Express 4 · axios · winston · nanoid
桌面：Tauri 2 · Rust · tauri-plugin-shell（sidecar）

---

## 说明与边界

- 代理/认证**已实现**：`httpClient` 支持 HTTP/SOCKS5 代理与 Basic/Cookie/自定义头认证；引擎默认仅监听 `127.0.0.1`，CORS 仅放行可信前端源，可选 `SCAN_API_TOKEN` 纵深防御（详见 `server/index.js`）。
- 时间盲注以「延迟 ≥ 基线 + 阈值且稳定多次」为判定，排除本身较慢的目标误报；布尔/报错注入均补了基线对照与二次确认。
- 单次拖库默认单表上限 100 行（可在 `defaults.js` 调整），UI 二次确认。
- Tauri sidecar 的 Node 二进制由 `build:engine` 脚本产出，本仓库不锁定打包工具。
