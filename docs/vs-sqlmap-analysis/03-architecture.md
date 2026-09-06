# 03. 架构 / 代码质量差距分析（对标 sqlmap）

> 只读分析，未修改任何代码。分析范围：`server/`（Node/Express 检测引擎）+ `src/`（React 前端）+ 装配入口。
> 对照基准：sqlmap 以 `lib/` 下 controller / core / request / techniques / tamper 等模块化分层 + 全局配置系统 + 单进程 CLI 生命周期管理著称。
> 结论先行：本项目**分层骨架清晰、检测逻辑单测充分（后端 362 用例全绿）**，但存在 4 个 P0 级工程/安全缺陷（内存泄漏、SSE 连接泄漏、`sessionFile` 任意文件读写、限速配置失效），以及若干层间倒置、重复代码与遗留物。详见下文。

---

## 1. 架构现状梳理

### 1.1 分层图（自外向内）

```
┌─ Entry ── server/index.js（Express 装配 / 双前缀挂载 / CORS 白名单 / 可选 Token / 兜底错误处理）
│            · 同时挂载 /api/* 与 /*（Web 版 base=/api，Tauri 版 base=http://127.0.0.1:4567）
│            · /api/sqlmap 与 /sqlmap 走混合架构（sqlmapBridge）
├─ api 层 ── server/src/api/*.js（入参 sanitize + 路由 + 统一响应 {code,data,message}）
│            scanRoutes / exploitRoutes / sqlmapRoutes / tamperRoutes / healthRoutes
├─ engine 层（domain）── server/src/engine/*
│            ScanManager（门面，唯一编排器）
│              ├─ TargetParser（注入点发现/表单爬取）→ DBFingerprinter（指纹）
│              ├─ detectors/*（策略模式 9 个检测器，扫描器内注册表调度）
│              ├─ Extractor（枚举/拖库/盲注二分）← ColumnTypeEnumerator
│              ├─ Exploiter（sql-shell/file-read/file-write/os-shell/UDF/注册表）
│              └─ injection.js / payloads.js / models.js / columnGuess.js
│            engines/sqlmapBridge.js（spawn sqlmap CLI，流式输出→SSE）
├─ services 层 ── server/src/services/*
│            Scheduler（并发池+重试）/ ReportGenerator（报告/风险定级/HTML 导出）
├─ core 层（infra）── server/src/core/*
│            httpClient（令牌桶+重试+代理/认证/WAF 头）· eventBus（SSE）· sessionStore（resume）
│            logger / errors / oobReceiver / directConnector / dbDrivers
│            tamper/*（TamperRegistry + 62 插件 + applyTampers）
│            waf/*（WafIdentifier / wafRules / wafRecommend）
└─ config ── server/src/config/defaults.js（集中默认参数）
前端 src/：store/scanStore.ts（zustand 单一数据源）+ hooks/useScan.ts + hooks/useEvents.ts（SSE）
          + shared/{types,apiClient,tauriBridge,constants}.ts（双形态契约层）
```

### 1.2 关键文件与规模

| 文件 | 行数 | 职责 |
|---|---|---|
| `server/src/engine/ScanManager.js` | 539 | 门面：发现→指纹→分层调度→聚合→提取→报告，附二阶/NoSQL 补充趟 |
| `server/src/engine/Exploiter.js` | 578 | 利用能力（注入 SQL 到目标，非本地 RCE） |
| `server/src/engine/Extractor.js` | 495 | 枚举/拖库/盲注二分提取 |
| `server/src/engine/payloads.js` | 490+ | Payload 模板库 + 检测技术枚举 + 签名 |
| `server/src/engines/sqlmapBridge.js` | 262 | sqlmap CLI 桥（spawn 数组参数，防注入） |
| `server/src/core/httpClient.js` | 178 | 唯一出站通道（令牌桶/重试/代理/认证） |
| `server/src/core/eventBus.js` | 71 | 按 scanId 隔离的事件 + SSE 推送 |
| `server/index.js` | 85 | Express 装配 |

### 1.3 与 sqlmap 的对应关系

- `ScanManager._run` ≈ sqlmap `controller/` 主流程（discover→detect→exploit→report）；
- `detectors/*` ≈ sqlmap `techniques/`（union/error/boolean/time/stacked/oob 一一对应）；
- `tamper/*` ≈ sqlmap `tamper/`（62 内置插件，链式可插拔）；
- `payloads.js` ≈ sqlmap `data/xml/` 载荷库（按 DBMS × 技术分类）；
- `Extractor` ≈ sqlmap `lib/request/` 的 data 提取通道；
- `sqlmapBridge` = 本项目"混合架构"特有的外部引擎托管层。

整体模块化程度已达 sqlmap 的 70% 左右体量；主要差距在**工程质量护栏**（生命周期/资源回收/配置白名单/CI 门禁），而非模块划分本身。

---

## 2. 问题清单

> 严重度：**P0** = 会引发资源泄漏/宿主文件访问/功能失效；**P1** = 架构倒置/重复代码/契约漂移；**P2** = 测试与维护性欠账。

### P0-01 内置引擎扫描上下文永不回收（内存泄漏 + 拖库数据滞留）
- **位置**：`server/src/engine/ScanManager.js:64`（`this.scans = new Map()`，start/set 后**从未 delete**）；`server/src/core/eventBus.js:63`（`dispose` 定义了，但 `ScanManager._run` 全程不调用；唯一调用点在 `sqlmapBridge.js:238`）
- **影响**：每次扫描在 `scans` Map 与 `emitters` Map 各留一条永久条目；report 含拖库全量数据（`report.data` 可能极大）。引擎长时间运行内存只增不减；`emitters` 的 EventEmitter 虽随连接 close 移除 listener，但发射器本体永不销毁。
- **严重度**：P0（服务器场景必现，呈线性增长）

### P0-02 SSE 对未知 scanId 只 write 不 end（连接泄漏）
- **位置**：`server/src/core/eventBus.js:35-45`（`!em` 分支写完 `scan_error` 后 `return`，未 `res.end()`）
- **影响**：客户端订阅一个不存在/已回收的 scanId 时，HTTP 响应永不关闭、心跳 `setInterval` 也**未启动**（无害但连接悬挂），浏览器将反复重连，连接逐步堆积。
- **严重度**：P0（配合 P0-01 的 dispose 缺失，构成双重连接/内存泄漏）

### P0-03 `sessionFile` 未校验 → 引擎宿主任意文件读/写
- **位置**：`server/src/api/scanRoutes.js:38`（`...cfg` 全量透传，`sessionFile` 无白名单）；`server/src/engine/ScanManager.js:160-170`；`server/src/core/sessionStore.js:79-87,90-104`
- **影响**：`POST /scan/start` 可携带 `config.sessionFile` 指向宿主任意路径。`ScanSession.load` 对任意路径 `fs.readFile`（任意文件读）；`_flush`/`finalize` 对任意路径 `fs.writeFile`（内容为攻击者可影响的 JSON 快照，任意文件写）。引擎默认监听 `127.0.0.1:4567`、`SCAN_API_TOKEN` 默认关闭，任何本地进程即可触发。
- **严重度**：**P0（引擎宿主侧安全漏洞，超出"扫描目标"范畴）**

### P0-04 前端"限速"配置对引擎无效（ratePerSec 静默失效）
- **位置**：`server/src/core/httpClient.js:120-121`（单例桶固定 `defaults.ratePerSec`）；`request()` 不读取 `opts.ratePerSec`（httpClient.js:137-162）；`scanRoutes.js:39` 对 `ratePerSec` 做了 clamp 但无消费方；`Scheduler.js:8` 明说"保留参数"。
- **影响**：用户在 UI 设置限速 1~20 req/s 完全不生效，实际恒为全局默认 3 req/s；多个扫描共享同一全局令牌桶，互相拖慢且无法按扫描调控；同时产生"配置看起来生效"的假象。
- **严重度**：P0（功能失效 + 契约误导）

### P0-05 内置引擎无并发扫描上限（可被无限提交）
- **位置**：`server/src/api/scanRoutes.js:100`（模块级单例 `new ScanManager()`）；`ScanManager.start`（ScanManager.js:72-92）无容量检查
- **影响**：对比 `sqlmapBridge.maxConcurrent=2`（sqlmapBridge.js:115），内置引擎对并发扫描不设限；本地进程可连续 `POST /scan/start`，每个扫描展开大量并发 HTTP（4 检测器×并发 4×采样），瞬间打满本机连接与内存。
- **严重度**：P0（DoS 面）

### P0-06 配置透传白名单缺口（嵌套参数任意放大）
- **位置**：`server/src/api/scanRoutes.js:37-44`（`...cfg` 展开后仅 clamp 5 个顶层字段）
- **影响**：`extractConcurrency`、`dumpMaxRows`、`timeBlindSamples`、`blindRobust.*`、`jitterMs`、`maxColumnsGuess`、`dumpRowLimit` 等未收敛，可传 `extractConcurrency:1e9`、`dumpMaxRows:1e12`，放大请求量与提取量（对目标与引擎自身都是负担）。
- **严重度**：P0（入参校验不完整，直接影响请求放大）

### P0-07 引擎启动即 `listen`，无优雅关闭/信号处理
- **位置**：`server/index.js:81-83`（模块顶层 `app.listen`）；无 `process.on('SIGINT'/'SIGTERM')` 关闭 `oobReceiver`/HTTP server/在跑扫描
- **影响**：被终止时正在进行的扫描/SSE 连接直接断，OOB 接收端端口残留；Tauri sidecar 重启后端口被占的风险；也使 app 装配无法被注入式单测（测试只能 spawn 子进程，见 `engine.e2e.test.js:13-15`）。
- **严重度**：P1（进程级健壮性，运维/Tauri 重启场景）

### P1-08 分层倒置：core/tamper 依赖 engine/payloads
- **位置**：`server/src/core/tamper/applyTampers.js:2`（`import { obfuscatePayload } from '../../engine/payloads.js'`）；反向依赖方 `engine/Detector.js:2-4`、`engine/Extractor.js:4`、`engine/injection.js:3`
- **影响**：infra（core）向上依赖 domain（engine），一旦 payloads.js 需要引用 tamper 即形成真循环；当前靠"payloads 不回头 import"侥幸无环。属于可维护性隐患而非即崩问题。
- **严重度**：P1

### P1-09 请求构造逻辑三份复制（"集中维护"未落地）
- **位置**：`engine/injection.js:7-41`（`buildInjectionRequest`，注释称"集中维护避免三处漂移"）vs `engine/Detector.js:28-61`（`buildRequest`）vs `engine/Extractor.js:132-160`（`_build`）
- **影响**：三处逐字相近但各自独立演进；`Detector.buildRequest` 未委托 `buildInjectionRequest`（仅 direct 模式委托）。DBFingerprinter 用 injection.js、检测器/提取器用各自副本，新增注入位置（如 header）需同步改三处。
- **严重度**：P1

### P1-10 `WRAP` 包裹器重复定义且已漂移
- **位置**：`engine/Extractor.js:7-18` vs `engine/DBFingerprinter.js:8-24`
- **影响**：同一结构两份定义；Extractor 版覆盖 7 库，DBFingerprinter 版扩展了 C 方向 6 库（DB2/Firebird/Informix/H2/Sybase）。后续加库必然只改一处导致漂移。
- **严重度**：P1

### P1-11 HTML 表单解析重复三处
- **位置**：`engine/TargetParser.js:91-134`（`_parseForms`/`_attr`）vs `engine/detectors/SecondOrderDetector.js:165-191`（`_parseFormsForToken`/`_attr`）
- **影响**：正则解析 `<form>/<input>` 两份实现，行为不一致时（如 CSRF 重抓）排查成本高。
- **严重度**：P1

### P1-12 `ReportGenerator.build` 是死代码
- **位置**：`server/src/services/ReportGenerator.js:11-30`（`build` 无任何调用方；实际走 `ScanManager._run` 内联装配 + `createReport`）
- **影响**：维护者可能误以为 `build` 是报告主入口；`summary.totalPoints` 等字段实际未生成，与报告实际结构分叉。
- **严重度**：P1

### P1-13 Tauri 版报告导出未接桥（window.open + 预留死代码）
- **位置**：`src/hooks/useScan.ts:86-89`（`exportReport` 恒用 `window.open`）；`src/components/ReportExport.tsx:15`（`void tauriBridge` 预留，`tauriBridge.saveFile` 从未被调）
- **影响**：桌面端导出报告依赖 webview 的 `window.open` 下载，行为不确定（可能弹空白窗/被拦截）；与已实现的 `tauriBridge.saveFile`（tauriBridge.ts:31-50）形成"双实现，一真一假"。
- **严重度**：P1（功能不完整）

### P1-14 全局模块级单例 + 无 DI，测试靠 monkey-patch
- **位置**：`scanRoutes.js:100`（`const sm = new ScanManager()`）、`exploitRoutes.js:56`（`new Exploiter()`）、`sqlmapRoutes.js:7`（`new SqlmapBridge()`）；测试如 `scanManager.scheduling.test.js:14-25` 直接改写 `sm.detectors`
- **影响**：多实例/配置化/可测性受限；`Exploiter` 在 exploitRoutes 与 ScanManager 各建一份，`colTypeCache` 等状态无法共享。
- **严重度**：P1

### P1-15 日志直出 `console.warn` 未走 logger
- **位置**：`services/Scheduler.js:39`、`core/dbDrivers.js:124`
- **影响**：与统一 winston 通道（含文件落盘、级别控制）分叉，生产排障丢日志。
- **严重度**：P2

### P1-16 令牌桶等待后令牌清零
- **位置**：`server/src/core/httpClient.js:21-33`（`acquire` 在 `setTimeout` 后直接 `this.tokens = 0`，`this.last` 未刷新）
- **影响**：等待期间按速率累积的令牌被丢弃，实际速率略低于设定值；长等待后误差更明显（结合 P0-04 的 ratePerSec 失效，此桶语义基本无人真正校准）。
- **严重度**：P2

### P1-17 HTTP 超时路径不重试（"第 N 次重试"日志误导）
- **位置**：`server/src/core/httpClient.js:164-171`（catch 内命中超时立即 `throw new AppError(HTTP_TIMEOUT)`，`retry` 循环对超时无效；日志却写"第 attempt+1 次重试"）
- **影响**：timeoutMs 或 retry 语义与实现不符；慢目标上时间盲注基线与注入请求一超时就整体失败，不回退。
- **严重度**：P1（若设计有意不重试超时，应改文案并加注释）

### P1-18 会话落盘非原子写
- **位置**：`server/src/core/sessionStore.js:79-87`（直接 `writeFile`，无临时文件+rename）
- **影响**：并发扫描（每点完成即 flush）或进程中断可能写坏 JSON；resume 读到损坏文件时 `ScanSession.load` 返回 null（静默丢进度）。
- **严重度**：P2

### P1-19 前后端类型契约漂移
- **位置**：后端 `engine/payloads.js:9` `TECHNIQUE_TYPES` 含 `'second_order'`；前端 `src/shared/types.ts:10` `TechniqueType` 缺 `second_order`；`src/shared/constants.ts:10` `TECHNIQUES` 缺 `oob`；`types.ts:270` `ScanEvent.payload: any`
- **影响**：报告/事件里的 `technique:'second_order'` 前端类型无法表达；payload 无类型导致事件解构全靠 `as any`（如 ProgressView.tsx:34,43）。
- **严重度**：P2

### P2-20 测试覆盖缺口（关键逻辑无直接单测）
- **位置**：`services/Scheduler.js`（`run` 的并发/重试逻辑无直接测试，仅经 ScanManager 以 concurrency:1 间接跑过）；`core/httpClient.js`（request 的超时/重试/令牌桶无测试，`httpClient.p2.test.js` 只测 buildProxyAgent/mergeAuthHeaders）；`core/eventBus.js` `toSSE` 的 cleanup/`res.end` 未测（`eventBus.test.js:48-53` 只断言 write 内容）
- **影响**：P0-02/P0-04/P1-17 正因此类缺口未被早期发现。
- **严重度**：P1

### P2-21 遗留文件与多日志位置
- **位置**：根 `nul`（358B，Windows `dir /s /b` 重定向误产）；`.trash/nul.bak-20260803`；`server/src/core/logger.js.bak-20260728-0128`；游离日志 `server/engine.log`(18KB) / `server/logs/engine.log` / `logs/engine.log`(0B) 三处并存；根 `debug-target.mjs`、`live-scan-demo.mjs`、`.mock/sqlmap.py`（均为 .gitignore 已覆盖的开发残留）
- **影响**：工作区噪音；`*.log` 三处位置导致"看哪份日志"困惑。
- **严重度**：P2

### P2-22 前端测试在默认并行下异常慢 / 挂起
- **位置**：`package.json:16`（`vitest run` 默认文件级并行）；实测默认并行 >5min 无输出，`--no-file-parallelism` 后 34s 全绿（12 文件/48 用例）；`appMount.smoke.test.tsx` 挂载 App 触发 `WafTamperPanel` 真实 axios 请求，jsdom 无服务 → 控制台刷 `AggregateError` 噪音
- **影响**：CI 前端测试不可控；噪音掩盖真实失败。
- **严重度**：P2

### P2-23 无覆盖率门禁
- **位置**：`vitest.config.ts:10-12`（`coverage.provider:'v8'` 已配但无 `thresholds`，且默认流程不跑 `--coverage`）；`server/package.json:11`（`node --test` 无 coverage）
- **影响**：质量无法量化；P0-04/P0-06 这类"无人调用"的死配置/死参数正是无覆盖率反馈的表现。
- **严重度**：P2

### P2-24 根包无统一测试脚本
- **位置**：`package.json:16`（仅 `vitest run`）；后端需 `cd server && node --test`（`server/package.json:11`）
- **影响**：CI 需手写两段命令，易漏。
- **严重度**：P2

### 附：已核查为"非问题"（防误报）
- 无本地 `eval`/`new Function`/`execSync`；唯一 `spawn` 为 sqlmapBridge 数组参数（`sqlmapBridge.js:166`），参数白名单化（`buildArgs`），无命令注入。
- `Exploiter` 的 os-shell/file 能力是**注入到目标数据库**的 SQL（Exploiter.js:279-345），不是引擎本机执行，属产品功能面。
- CORS 白名单 + `express.json({limit:'2mb'})`（index.js:29-41）合理；`GET` 豁免 token 是有意设计（index.js:48 注释），但结合拖库报告可读性值得留意（见建议 A6）。
- 报告 HTML 导出对 description/payload/URL 做了 `_escape`（ReportGenerator.js:114-119），无 XSS。

---

## 3. 优化建议

> 每条：建议内容 / 预期影响 / 工作量 / 优先级。

### A1 扫描生命周期回收（P0-01/P0-02）
- **建议**：`ScanManager` 增加 `_retire(scanId)`：扫描 completed/stopped/error 后置 `s.retiredAt`，启动 30s TTL 定时清 `scans.delete(scanId)` 并 `eventBus.dispose(scanId)`；`toSSE` 的 `!em` 分支补 `res.end()`；为 `scans` Map 设上限（如 100）超限淘汰最旧。
- **预期影响**：消除内存/连接泄漏，服务器长跑稳定。
- **工作量**：S　**优先级**：P0

### A2 `sessionFile` 白名单化（P0-03）
- **建议**：在 `sanitizeStart`（scanRoutes.js:14-98）对 `sessionFile` 做校验：仅允许放行 `os.tmpdir()`/CWD 下文件名（如 `/tmp/sqli-session-*.json`），拒绝绝对路径、`..`、符号链接逃逸；或在引擎侧维护 `sessionDir` 配置并把 sessionFile 归一化为其子路径。
- **预期影响**：堵住引擎宿主任意文件读写面。
- **工作量**：S　**优先级**：P0

### A3 让限速配置真正生效（P0-04）
- **建议**：方案一（推荐）：`HttpClient.request` 增加 `ratePerSec` 透传，Detector.send/Extractor._send/sendInjection 从 `config.ratePerSec` 传入，请求前用**按扫描隔离的桶**（或从共享桶派生）；方案二：维持全局单桶但移除 `scanRoutes.js:39` 的无效 clamp，前端隐藏该设置。
- **预期影响**：限速设置可控、多扫描不互扰。
- **工作量**：M　**优先级**：P0

### A4 内置引擎并发扫描上限（P0-05）
- **建议**：复用 sqlmap 桥模式，给 `ScanManager` 加静态 `activeScanCount` + 上限（如 `MAX_SCAN_API_CONCURRENT`），超出返回 `ENGINE_BUSY`（错误码已存在，`errors.js:9`）。
- **预期影响**：杜绝本地进程无限制提交扫描造成 DoS。
- **工作量**：S　**优先级**：P0

### A5 配置全量白名单 + 边界 clamp（P0-06）
- **建议**：废弃 `...cfg` 盲展开（scanRoutes.js:38），改为显式逐字段收编：`extractConcurrency`(1~16)、`dumpMaxRows`(≤50000)、`timeBlindSamples`(3~10)、`jitterMs`(0~5000)、`maxColumnsGuess`(1~100)、`blindRobust.*`（布尔化 + 各采样数 clamp）、`dumpRowLimit`(1~1000)。
- **预期影响**：配置即契约，防参数放大与意外越界。
- **工作量**：M　**优先级**：P0

### A6 日志脱敏 + 报告访问护栏（配套）
- **建议**：logger 统一收口 URL 打印（`httpClient.js:167,170`、`scanRoutes.js:112`）：剥离 `user:pass@` 与常见凭据查询键（`token/session/password`），payload 证据只保留前 160 字符；`GET /scan/:id` 类报告读端点与拖库数据建议在 token 开启时同样受保护（或提供按扫描只读 token）。
- **预期影响**：日志/报告泄漏面收敛。
- **工作量**：S　**优先级**：P1

### A7 解耦 core→engine 反向依赖（P1-08）
- **建议**：把 `obfuscatePayload`（纯字符串变换）下沉到 `core/tamper/` 或新建 `shared/obfuscation.js`，`payloads.js` 与 `applyTampers.js` 共同引用；或反转：`applyTampers` 只接收变换函数参数，由 engine 注入 `obfuscatePayload`。
- **预期影响**：core 不再依赖 engine，消除潜在循环。
- **工作量**：S　**优先级**：P1

### A8 收敛请求构造与 WRAP/表单解析（P1-09/10/11）
- **建议**：`Detector.buildRequest`、`Extractor._build` 改为委托 `injection.js:buildInjectionRequest`（删除各自副本，保留签名兼容）；`WRAP` 合并为单一导出（建议以 DBFingerprinter 全量版为准，Extractor 引用它）；HTML 表单解析抽到 `core/` 或 `engine/` 共用模块。
- **预期影响**：单一事实源，改一处生效。
- **工作量**：M　**优先级**：P1

### A9 消除死代码并接通 Tauri 导出（P1-12/13）
- **建议**：删除 `ReportGenerator.build`（或让 `ScanManager` 改用它并补充 `summary` 字段）；`ReportExport` 改为检测 `tauriBridge.isTauri` 分支走 `saveFile`，Web 回退 `window.open`。
- **预期影响**：报告结构单一入口；桌面导出可用。
- **工作量**：S　**优先级**：P1

### A10 装配与生命周期治理（P0-07/P1-14）
- **建议**：`index.js` 拆分 `createApp()`（纯装配，可测）与 `start()`（listen + `SIGINT/SIGTERM` 时关闭 server/oobReceiver/dispose 全部扫描）；`scanRoutes`/`exploitRoutes`/`sqlmapRoutes` 改为工厂函数接收依赖实例（`createScanRouter(sm)`），默认注入单例。
- **预期影响**：app 可注入式测试；进程可优雅退出；实例可配置。
- **工作量**：M　**优先级**：P1

### A11 补齐关键路径单测（P2-20）
- **建议**：新增 `Scheduler.run` 直接测试（并发数/重试次数/失败隔离）、`HttpClient.request` 超时/重试/令牌桶测试、`eventBus.toSSE` 的 cleanup（close 后 listener 移除、`res.end`）、`sessionFile` 校验测试；为 P0-04 补"ratePerSec 生效"回归。
- **预期影响**：P0 类缺陷提前暴露。
- **工作量**：M　**优先级**：P1

### A12 前端测试与 CI 修复（P2-22/23/24）
- **建议**：`vitest.config.ts` 设 `fileParallelism:false`（或排查 Windows worker 挂起原因）；`appMount` 测试全局 stub `apiClient`；`package.json` 增加 `test:all`（先后端 `node --test` 再 `vitest run`）；配置 `coverage.thresholds`（如 server 核心函数 ≥70%）并纳入 CI。
- **预期影响**：CI 稳定 + 覆盖率可视化。
- **工作量**：S　**优先级**：P2

### A13 清理遗留物（P2-21）
- **建议**：删除 `nul`、`.trash/`、`logger.js.bak-*`、`server/engine.log`，统一日志仅落 `logs/engine.log`（logger.js:10 已含 CWD 探测，可顺带校验）；`.gitignore` 补 `.trash/`；`debug-target.mjs`/`live-scan-demo.mjs` 移入 `scripts/` 或删除。
- **预期影响**：工作区干净，减少误读。
- **工作量**：S　**优先级**：P2

### A14 补强规范与护栏（配套）
- **建议**：引入 ESLint（项目现无任何 lint 配置）、JSDoc 类型检查（`npx tsc --allowJs --checkJs` 或切 `.d.ts` 契约，优先让 `shared/types.ts` 反向约束后端），为 `core/tamper` 插件 transform 增加最小契约测试。
- **预期影响**：双形态契约不漂移（P1-19 根因）。
- **工作量**：M　**优先级**：P2

---

## 4. 总结（核心结论）

本项目分层骨架优于多数同类 Node 项目，后端 362 个测试全绿，检测判定（布尔/时间鲁棒路径）与 tamper/WAF 覆盖充分；但与 sqlmap 级别的工程成熟度相比，差距集中在"**资源生命周期治理**"与"**配置/安全白名单**"：① 扫描上下文与 SSE 连接永不回收（内存/连接泄漏），② `sessionFile` 未校验构成引擎宿主任意文件读写（P0 安全漏洞），③ 限速与嵌套配置"看似生效实则失效"（契约失真），④ 层间倒置与三处重复实现是后续扩展的地雷。**先修 4 个 P0（A1/A2/A3+A4/A5），再补关键单测（A11）即可显著提升工程质量。**
