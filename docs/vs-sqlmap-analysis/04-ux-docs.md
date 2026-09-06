# 04 · 体验/文档差距分析（对标 sqlmap 可用性）

> 只读分析任务 · 未修改任何项目代码 · 分析日期 2026-08-13
> 对照基准：sqlmap（CLI 工具，wiki 文档体系 20+ 页面）
> 结论先行：**功能面已覆盖 sqlmap 核心参数的 ~70%，但"结果闭环""文档体系""引导""日志"四个体验面存在系统性缺口，其中 sqlmap 高级模式的结果断链（无法查看报告/导出/进历史）是最高优先级的 P0。**

---

## 1. 现状梳理

### 1.1 前端页面与组件现状

| 页面/组件 | 路径 | 现状 |
|---|---|---|
| 扫描页 | `src/pages/ScanPage.tsx` | 双引擎切换（builtin/sqlmap）、目标录入、配置面板、WAF 建议横幅、开始/停止、拖库与破坏性操作二次确认 Dialog、实时进度区 |
| 目标录入 | `src/components/TargetForm.tsx` | URL + 方法（仅 GET/POST）+ Body/Cookie/Header（JSON 文本）；无注入点标记、无参数级 -p |
| 扫描配置 | `src/components/ScanConfigPanel.tsx` | 并发/超时/重试/时间盲注阈值/限速/拖库开关/代理/认证/技术勾选/WAF 规避；`mode==='sqlmap'` 时隐藏大部分内置项 |
| sqlmap 参数面板 | `src/components/SqlmapOptions.tsx` | level/risk/dbms/threads/technique(BEUSTQ)/tamper 预设(8 项)/dump/osShell/fileRead |
| WAF/tamper 面板 | `src/components/WafTamperPanel.tsx` | 总开关 + 三档强度预设 + 有序链式多选（62 项来自 `/api/tampers` 单一事实源）+ 上移/下移/删除 + WAF 推荐一键应用 |
| 漏洞列表/详情 | `src/components/VulnList.tsx` / `VulnDetail.tsx` | 列表=风险+技术+注入点+库名；详情=注入点/库/说明/盲注时间线/只读 Payload |
| 盲注时间线 | `src/components/BlindTraceTimeline.tsx` | 布尔/时间盲注统计判定证据链（基线采样、真假对、z 值、逐采样差异）——**本项目明显强于 sqlmap 的体验点** |
| 拖库树 | `src/components/DbTree.tsx` | 库→表→列→数据预览（前 20 行）递归树 |
| 报告导出 | `src/components/ReportExport.tsx` | JSON / HTML 两按钮；Tauri `tauriBridge.saveFile` 仅为预留（`void tauriBridge`），桌面落盘未接线 |
| 实时进度 | `src/components/ProgressView.tsx` | 状态 Chip + **indeterminate** 进度条 + 事件流（`max-h-72` 滚动，最多 300 条） |
| 报告页 | `src/pages/ReportPage.tsx` | 漏洞列表+详情+拖库树+导出；含 WAF/tamper 审计标注 |
| 历史页 | `src/pages/HistoryPage.tsx` | localStorage 持久化（`sqli_scan_history_v1`，上限 100），完整报告快照离线回溯 |
| 利用页 | `src/pages/ExploitPage.tsx` | SQL Shell / 读文件 / 写文件 / OS Shell 四 Tab + `authorized` 勾选 + 能力清单 Chip |
| 顶栏 | `src/components/TopBar.tsx` | 导航（新建扫描/历史/利用）+ 主题切换（浅色/跟随/暗色） |

### 1.2 引擎与 API 现状

- 路由挂载双前缀（`/api` 与 `/`），见 `server/index.js:59-70`；CORS 白名单 + 可选 `SCAN_API_TOKEN` + 仅监听 `127.0.0.1`（纵深防御做得好）。
- 内置引擎：`server/src/api/scanRoutes.js` → `ScanManager`，SSE 事件 12 类（`scan_started/point_discovered/point_testing/detection_found/extraction_progress/scan_completed/scan_stopped/scan_error/sqlmap_log/sqlmap_vuln/waf_detected`）。
- sqlmap 桥：`server/src/engines/sqlmapBridge.js` 把结构化请求翻译为 CLI 参数（数组形式 spawn，防注入），按前缀 `[+] [*] [~] [-] [!]` 分类输出行，`--batch` + `--output-dir` 写系统临时目录（`os.tmpdir()`）。
- 报告生成：`server/src/services/ReportGenerator.js`，风险定级（可提取=Critical/堆叠=Critical/回显=High/盲注=Medium/OOB=Medium/Low），HTML 导出为内联样式单页表格。
- 日志：`server/src/core/logger.js` 控制台 + 文件（**仅 warn 及以上落盘**）。
- 利用：`server/src/api/exploitRoutes.js`，`authorized:true` 硬校验（服务端安全底线明确）。

### 1.3 文档现状

- `README.md`：快速开始（双形态启动）、API 端点表（9 个端点）、默认参数表、风险定级、技术栈、边界说明。无截图、无示例输出、无 FAQ。
- `docs/`：14 个 `.md`（4422 行）+ 16 个 `.mermaid`，全部为**内部设计文档**：PRD（`prd_f19/20/p2/wafv2`）、系统设计（`system_design*.md`）、时序图/类图、`waf_runbook.md`（WAF 实战 runbook）、`blind_robust_design.md`。
- **缺失**：用户手册/使用指南、部署文档、FAQ、参数全说明、tamper 目录说明、API 参考文档（OpenAPI）、法律责任与授权声明文档。

---

## 2. 与 sqlmap 差距清单

> 按任务调研的 7 个方向组织。sqlmap 做法基于 sqlmap wiki Usage/Features 页与 CLI `-hh` 输出。

### 2.1 功能入口完整性

| # | 差距点 | sqlmap 做法 | 本项目现状 | 影响 |
|---|---|---|---|---|
| G1 | 注入点指定 | `-p id` 指定测试参数；URL/`--data`/`--cookie`/`--headers` 中用 `*` 标记精确注入点；`--skip`/`--skip-static` 跳过参数 | `TargetForm.tsx` 仅整体 URL/JSON 输入，无 `*` 标记、无 `-p` 入口。sqlmap 桥 `buildArgs`（`sqlmapBridge.js:57-59`）**已支持 `-p` 数组但前端从未传 `params`** | 无法针对单参数精扫；参数多时全量扫描浪费请求 |
| G2 | HTTP 方法 | `--method=PUT/PATCH/DELETE`、`-r` 从 Burp 请求文件导入 | `MethodType = 'GET' \| 'POST'`（`types.ts:4`），TargetForm 仅两项 | 无法测 REST API 的 PUT/PATCH 注入 |
| G3 | 请求精细控制 | `--delay`、`--timeout`、`--retries`、`--safe-url`、`--csrf-token`、`--chunked`、`--hpp`、`--eval` | 内置引擎有 timeout/retry/jitterMs；**sqlmap 模式仅透传 threads/level/risk/technique/tamper/dbms/dump/osShell/fileRead**（`SqlmapOptions.tsx`），timeout/retry/proxy/randomUA 均无映射字段 | sqlmap 模式下最常用的安全网（超时/重试/延时）丢失 |
| G4 | 代理/认证 | `--proxy`（http/socks5）、`--proxy-cred`、`--auth-type=Basic/Digest/NTLM`、`--auth-cred` | 内置引擎代理/认证完整（`ScanConfigPanel.tsx`）；**sqlmap 桥 `buildArgs:81-84` 已支持 `c.proxy`，但 `SqlmapConfig`（`types.ts:25-35`）没有 proxy/auth 字段，前端永远传不到**；认证仅 Basic | sqlmap 模式下无法走代理/带认证 |
| G5 | 检测技术开关 | `--technique=BEUSTQ`，默认全开 | 内置 6 项勾选（union/error/boolean/time/stacked/inline）+ sqlmap 面板 BEUSTQ 勾选；与 sqlmap 对齐度高 | 轻微：inline(Q) 默认不勾，与 sqlmap 默认 BEUSTQ 不同，需文档说明 |
| G6 | level/risk/dbms/threads | `--level 1-5`、`--risk 1-3`、`--dbms`、`--threads 1-10` | `SqlmapOptions.tsx` 完整覆盖且带范围校验 | 对齐度高，无差距 |
| G7 | payload 定制 | `--prefix`/`--suffix`、`--string`/`--not-string`/`--regexp`/`--code`、`--union-cols`/`--union-char` | 无任何入口（内置引擎 `payloads.js` 固定模板，仅可读） | 无法处理自定义闭合场景（如 `')--`），遇到特殊语法只能放弃或改源码 |
| G8 | random-agent | `--random-agent` / 自定义 `--user-agent` | 内置 `wafEvasion.randomUA` 开关（`ScanConfigPanel.tsx:245`）；**sqlmap 模式无对应开关**；自定义 UA 无入口 | sqlmap 模式下默认 UA 暴露工具特征 |
| G9 | tamper 选择 | `--tamper=xxx,yyy`，`--list-tampers` 列出 100+ 脚本 | 内置 62 项（`/api/tampers`，单一事实源）+ 强度预设 + 链式排序 + WAF 推荐；**sqlmap 面板仅 8 个硬编码预设**（`constants.ts:105-114`） | 内置体系体验超越 sqlmap；sqlmap 模式 tamper 覆盖面窄 |
| G10 | 批处理/非交互 | `--batch` 免交互、`--answers` 预置回答 | 内置引擎无交互点；sqlmap 桥固定追加 `--batch`（`sqlmapBridge.js:104`） | 对齐，无差距 |
| G11 | 并发/限速 | `--threads`；本身无限速但有 `--delay` | 内置引擎并发+令牌桶限速（`defaults.js`），UI 可调 | 内置引擎限速能力优于 sqlmap 默认；但 sqlmap 模式 `--threads` 固定透传 |

### 2.2 结果呈现

| # | 差距点 | sqlmap 做法 | 本项目现状 | 影响 |
|---|---|---|---|---|
| G12 | sqlmap 模式结果断链 | 扫描后终端输出 + `--output-dir` 落盘，可随时查看 | **sqlmap 模式完成事件（`useEvents.ts:36-42`）仅 `engine==='builtin'` 才 setReport/saveScanToHistory；前端无任何 `/sqlmap/:id/report` 的消费方；`ReportPage` 走 `/scan/:id/report` 对 sqlmap 扫描返回 404**。`SqlmapBridge.getReport` 只有 `{logs, vulns}`，无 ReportModel 结构 | **P0：sqlmap 高级模式扫描完看不到结果、不能导出、不进历史，闭环断裂** |
| G13 | 漏洞详情证据 | sqlmap `-v 3` 显示完整 Payload 与 HTTP 请求/响应，`-t` 记录全流量 | `VulnDetail.tsx` 显示注入点/库/说明/只读 Payload/盲注时间线；**无原始请求/响应证据、无响应片段、无复现按钮** | 报告不可审计、不可复现；`DetectionResult.evidence` 字段（`types.ts:207-214`）已存在但详情页未展示 |
| G14 | 漏洞列表信息量 | sqlmap 输出含 DBMS banner、当前用户、当前库、注入技术 | `VulnList.tsx` 仅风险+技术+注入点+库名；无 banner/用户/版本细节 | 信息密度低于 sqlmap 终端 |
| G15 | 拖库结果导出 | `--dump` + `--dump-format=CSV/JSON/HTML` 落盘，可按 `-D/-T/-C` 定向 | `DbTree.tsx` 树形展示（前 20 行预览）+ 报告内嵌；**拖库数据无法单独导出 CSV** | 拖库数据只能留在报告 JSON 里，无法交差/入库 |
| G16 | 进度可感知度 | sqlmap 有 ETA、当前任务、按 DBMS/表细粒度状态行；`-v 0-6` 调粒度 | `ProgressView.tsx` 进度条为 **indeterminate**（无百分比/ETA），事件流仅单列 | 长扫描无法预判耗时；无粒度调节 |

### 2.3 报告输出

| # | 差距点 | sqlmap 做法 | 本项目现状 | 影响 |
|---|---|---|---|---|
| G17 | 导出格式 | `--dump-format` 支持 CSV/JSON/HTML；`--output-dir` 自动生成 `session`/`log`/`data` 文件 | `ReportExport.tsx` 仅 JSON/HTML；`ReportGenerator.toHTML` 为单页简单表格（无请求/响应日志、无证据、无拖库明细） | 无 CSV 无法对接表格工具；HTML 报告审计价值低 |
| G18 | 详细请求/响应日志 | `-t` 把全部 HTTP 通信写文件；`-v 6` 输出完整请求/响应 | **引擎无全量请求/响应日志**（`logger.js` 文件仅 warn 级）；检测细节只通过 SSE 事件短暂在内存，`scan_completed` 60s 后 dispose（`eventBus.dispose`） | 无法事后审计"工具到底对目标发过什么"，是合规/取证关键缺口 |
| G19 | 会话持久化/续跑 | `--session`（sqlite）+ `--resume` 断点续跑、`--flush-session` | 无 session 概念；sqlmap 子进程 `--output-dir` 写系统临时目录，扫描结束即弃 | 长扫描中断（网络/断电）后全部重来；无断点恢复 |

### 2.4 文档差距

| # | 差距点 | sqlmap 做法 | 本项目现状 | 影响 |
|---|---|---|---|---|
| G20 | 文档体系 | wiki 20+ 页：Introduction/Techniques/Features/Usage（全参数分组详解含示例）/FAQ/History/License/Screenshots/Presentations/Dependencies；另有 `-h`/`-hh` 内建帮助 | 仅 README（快速开始+端点表）；`docs/` 全是内部设计文档（PRD/架构/时序图），**面向用户的手册为 0** | 新用户无从了解能力边界与参数含义，只能读代码 |
| G21 | 参数说明 | Usage 页逐参数：含义/默认/示例 | README 仅列 7 个引擎默认参数；`ScanConfigPanel`/`SqlmapOptions` 的参数无集中说明文档；`defaults.js` 注释是唯一权威 | 用户不知道 tamper 强度三档、自适应盲注、OOB 等高级项在干嘛 |
| G22 | 部署文档 | 官网安装说明（tar.gz/zip/git clone/Python 版本要求），跨平台 | README 有双形态启动命令，但**无生产部署、无环境要求（Node 版本）、无 Windows/macOS 打包细节、无 `build:engine` 具体命令（package.json 中是 echo 占位）** | 桌面版实际构建不可复现 |
| G23 | FAQ/排错 | wiki FAQ 页 | 无 FAQ；错误码（`errors.js`）无文档 | 报错后无处查原因 |
| G24 | 法律/授权文档 | 官网/README 强调授权（弱） | README 顶部一句声明 + 各 Dialog 二次确认；**无独立的合规使用文档/免责条款页** | 面向交付场景缺正式声明 |

### 2.5 CLI/API 可用性

| # | 差距点 | sqlmap 做法 | 本项目现状 | 影响 |
|---|---|---|---|---|
| G25 | CLI 模式 | sqlmap 本身就是 CLI：`python sqlmap.py -u ...`，`-h`/`-hh` 帮助 | **引擎无 CLI 模式**（`server/index.js` 仅 HTTP server；`server/scripts/*.mjs` 是 demo，非正式 CLI）；根目录 `live-scan-demo.mjs`/`debug-target.mjs` 为调试脚本 | 无法在 CI/自动化/无 UI 环境跑扫描，无法脚本化 |
| G26 | API 文档 | 无 REST API（sqlmap 是 CLI）；但它的参数就是"API" | README 只有 9 行端点表；**无 OpenAPI/Swagger、无请求/响应示例、无错误码表（`errors.js` 的 ErrorCode 无文档）、无入参字段说明**（`sanitizeStart` 的兼容双形态契约未文档化） | 二次集成成本高；前后端契约靠读源码 |
| G27 | sqlmap 可用性探测 | 无（sqlmap 自带） | 后端已有 `GET /sqlmap/status`（`sqlmapRoutes.js:12`）返回 available/script/python/maxConcurrent，**前端从未调用** | 用户切到 sqlmap 模式、点击开始后才报"未找到 sqlmap 脚本"（`sqlmapBridge.js:136-138`），体验差 |

### 2.6 用户引导

| # | 差距点 | sqlmap 做法 | 本项目现状 | 影响 |
|---|---|---|---|---|
| G28 | 首次使用引导 | CLI 有 `-h` 帮助即引导 | 无欢迎页/首次引导/示例 URL/教学靶场链接 | 首次用户不知道该填什么、会有什么后果 |
| G29 | 目标合法性提醒 | README + 社区惯例（弱） | **本项目是亮点**：README 声明、拖库 Dialog、破坏性操作 Dialog、利用页 `authorized` 勾选、WAF/tamper 默认关 | 保持即可；缺一次性启动免责确认 |
| G30 | 错误提示质量 | 彩色日志分级（[!] [x] [+] [*]） | 前后端均有校验（URL 空/JSON 非法/协议非 http/https/proxy 格式），Alert 展示 message；**但 sqlmap 启动失败、目标不可达等网络层错误信息粗糙**（`apiClient` 拦截器只透传 message） | 网络错误/后端未启动时提示不友好 |
| G31 | 利用页上下文回填 | sqlmap 从扫描会话直接复用注入点上下文 | `ExploitPage.tsx` 需**手动重填 URL/参数/原始值/DBMS**，与扫描结果零联动；且 `buildTarget` 硬编码 `authorized:true`（`ExploitPage.tsx:62`）——`run()` 的勾选校验只是前置拦截，请求体永远带 true | 从"发现漏洞"到"利用"断层；authorized 硬编码是绕过风险 |

### 2.7 日志

| # | 差距点 | sqlmap 做法 | 本项目现状 | 影响 |
|---|---|---|---|---|
| G32 | 日志级别 | `-v 0-6` 可调，`[INFO]/[WARNING]/[ERROR]` 清晰分级 | 文件日志 `level:'warn'`（`logger.js:32`），**info/debug 只上控制台不落盘**；实测 `server/logs/engine.log` 只有重复的"二阶检测已开启"警告 | 日志基本不可用于排障；无扫描级日志（谁扫了哪个目标、结果如何） |
| G33 | 脱敏 | 无内建脱敏（社区工具处理） | **无脱敏**：认证配置明文持久化（`ScanConfigPanel.tsx:131` 已明示"明文保存于本地"）；日志/事件/报告原样记录 Cookie/Header（含 session token） | 凭证泄露风险；报告分享时会外泄会话 |
| G34 | 日志查询 | `--output-dir` 下 log/session 文件可检索 | 事件流内存态 60s 后 dispose，无历史日志查询入口 | 无法追溯历史扫描细节 |

---

## 3. 优化建议

| # | 建议内容 | 预期影响 | 工作量 | 优先级 |
|---|---|---|---|---|
| S1 | **接通 sqlmap 模式结果闭环**：`useEvents.ts` 在 `scan_completed`（engine=sqlmap）时改为调用 `GET /sqlmap/:id/report` 并把 `{logs,vulns}` 包装为前端可渲染的视图（在 ReportPage 增加 sqlmap 报告分支），并 `saveScanToHistory`；`ReportPage`/`useScan.getReport` 按引擎路由到 `/sqlmap/:id/report` | 修复 G12，sqlmap 高级模式从"只能看实时日志"变为可回溯/导出 | M | **P0** |
| S2 | **打通 sqlmap 模式参数透传**：`SqlmapConfig`（`types.ts`）增加 `proxy`/`timeoutMs`/`retry`/`randomUA` 字段并在 `SqlmapOptions.tsx` 加 UI、`useScan.ts` startScan 透传；把内置面板的代理/认证/超时/重试在 sqlmap 模式复用（不要 `mode==='sqlmap'` 时隐藏掉） | 修复 G3/G4/G8，sqlmap 模式具备完整请求控制 | M | **P0** |
| S3 | **调用 `/sqlmap/status` 预检**：ScanPage 切到 sqlmap 引擎时请求 status，脚本缺失时 Alert 提前提示并给出 `SQLMAP_PATH`/clone 指引（`sqlmapBridge.js:136` 已有文案，前端复用） | 修复 G27，错误前置 | S | P1 |
| S4 | **全量请求/响应日志**：`httpClient.js` 增加可选 traffic 日志（每个请求 URL/方法/headers/body + 状态码/响应摘要/耗时），按 scanId 落文件到 `logs/traffic/<scanId>.log`，报告可附带下载；对标 sqlmap `-t` | 修复 G18，审计与合规取证能力；对接报告导出 | L | **P0** |
| S5 | **漏洞详情补证据**：`VulnDetail.tsx` 展示 `DetectionResult.evidence`（响应片段/请求摘要）与关键 payload 的完整请求；盲注已有 `BlindTraceTimeline`，把 union/error 的请求/响应证据补上 | 修复 G13，报告可复现可审计 | M | P1 |
| S6 | **导出格式扩展**：`ReportExport.tsx` + `ReportGenerator` 增加 CSV（漏洞表 + 拖库数据两档）；Markdown 可选 | 修复 G17，对接文档/表格工具 | M | P1 |
| S7 | **拖库数据单独导出**：DbTree 增加"导出该表 CSV/JSON"按钮（`/scan/:id/report/export?format=csv&table=db.table` 或前端从 report 切片） | 修复 G15 | S | P2 |
| S8 | **进度条真实化**：`ProgressView.tsx` 用已探测参数数/已完成技术数计算 determinate 百分比 + 剩余参数估计；事件流增加"复制日志""下载日志" | 修复 G16，长扫描可感知 | S | P2 |
| S9 | **注入点精确指定**：`TargetForm.tsx` 在 Body/Cookie/Header JSON 中支持 `"id": "1*"` 标记注入点，`useScan`/`sanitizeStart` 解析 `*` 位置生成 `-p`（sqlmap 桥 `buildArgs` 已支持 `params` 数组） | 修复 G1，精扫省请求 | M | P1 |
| S10 | **HTTP 方法扩展**：`types.ts` MethodType 增加 PUT/PATCH/DELETE，TargetForm 下拉补充；sqlmap 桥已有 `--method` 透传 | 修复 G2 | S | P2 |
| S11 | **payload 前缀/后缀入口**：ScanConfigPanel 或 SqlmapOptions 增加 prefix/suffix 输入，内置引擎 `applyTampers`/payload 生成处拼接，sqlmap 模式透传 `--prefix/--suffix` | 修复 G7，适配特殊闭合 | M | P2 |
| S12 | **CLI 模式**：`server/bin/cli.js` 包装 `ScanManager`，支持 `node server/bin/cli.js -u <url> [--technique] [--dump] [--json-out]`，复用 `sanitizeStart` 校验；`package.json` 增加 `sqli-scan` bin | 修复 G25，可脚本化/CI 集成 | M | P1 |
| S13 | **REST API 文档**：新增 `docs/api.md`（各端点请求/响应示例、错误码表来自 `errors.js`、`/scan/start` 双形态入参契约、SSE 事件表）；README 链接之 | 修复 G26，降低集成成本 | S | P1 |
| S14 | **用户手册**：新增 `docs/user-guide.md`（四页面操作、双引擎差异、tamper 强度说明、拖库与利用的合规红线、默认参数表、示例演练）；README 增加截图 | 修复 G20/G21/G28，让 30+ 份内部文档之外有面向用户的一页手册 | M | P1 |
| S15 | **FAQ 与部署文档**：`docs/faq.md`（常见报错/限速与误报/目标不可达/桌面版打包）；`docs/deploy.md`（Node 版本要求、生产部署、`build:engine` 具体化） | 修复 G22/G23 | S | P2 |
| S16 | **日志分级与脱敏**：`logger.js` 文件日志级别降为 info 并加 rotation；对 URL query 中常见敏感键（token/session/secret/password）打码；`ScanConfigPanel` 明文提示保留，持久化改为可选（localStorage 不存认证/代理） | 修复 G32/G33 | M | P1 |
| S17 | **会话续跑**：内置引擎与 sqlmap 桥增加 `--resume`/session 持久化（sqlmap 模式把 `--output-dir` 从 `os.tmpdir()` 迁到 `logs/sessions/<scanId>` 并保留），UI 历史页提供"续跑" | 修复 G19 | L | P2 |
| S18 | **利用页联动与修复**：`ExploitPage.tsx` 从扫描报告选择注入点自动回填（URL/参数/原始值/DBMS）；移除 `buildTarget` 中硬编码 `authorized:true`，改为携带勾选态 | 修复 G31，且消除绕过风险 | M | **P0** |
| S19 | **一次性免责声明**：首次启动展示授权合规 Dialog（勾选"已知晓"存 localStorage）；README 与报告 HTML 增加合规页脚 | 修复 G29/G24 | S | P2 |
| S20 | **sqlmap 面板 tamper 扩展**：`SqlmapOptions.tsx` 的 tamper 预设改为从 `/api/tampers` 动态拉取（复用 `WafTamperPanel` 逻辑）替代 8 个硬编码 | 修复 G9 | S | P2 |

---

## 4. 核心结论

1. 内置引擎的检测能力与可视化（盲注时间线、拖库树、SSE 进度、WAF/tamper 推荐链）在体验上已局部超越 sqlmap，但 **sqlmap 高级模式的结果闭环断裂**（无报告/导出/历史）是最先要修的 P0。
2. 参数面覆盖 sqlmap 常用项约 70%，缺口集中在精确注入点、方法扩展、payload 定制、sqlmap 模式的代理/超时透传。
3. 文档体系是最大短板：14 份内部设计文档 + 1 份 README，缺用户手册/FAQ/部署/API 文档，无法对标 sqlmap wiki 的 Usage/FAQ 体系。
4. 无 CLI 模式、无全量请求/响应日志、日志仅 warn 落盘且不脱敏——这三项是脚本化、审计合规与排障的关键缺口。
5. 安全与合规引导（二次确认、authorized 勾选、服务端校验）已做得较好，但利用页 `authorized` 硬编码与 sqlmap 可用性零预检需尽快修复。
