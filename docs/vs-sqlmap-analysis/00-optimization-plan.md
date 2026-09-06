# sqli-scanner 对标 sqlmap 全面优化方案（整合版）

> 来源：4 个子代理并行分析报告（01-detection / 02-performance / 03-architecture / 04-ux-docs）
> 原则：P0=高价值低成本（安全/正确性优先），P1=高价值中成本，P2=锦上添花
> 所有报告原文见本目录 01-04.md，本文件为去重整合后的执行主方案

---

## 0. 总览

| 维度 | 现状亮点 | 最大短板 |
|---|---|---|
| 检测能力 | 盲注统计判定（z 检验+自适应阈值）、62 个 tamper | 数字上下文漏检、时间盲注不能提取、tamper 破坏提取标记 |
| 性能 | 盲注二分+多位置并行结构接近 sqlmap | 全局令牌桶 3 req/s 锁死吞吐、重复劳动占 1/3 请求 |
| 架构 | 分层清晰、后端 362 测试全绿 | 扫描上下文泄漏、sessionFile 任意文件读写、限速配置失效 |
| 体验 | 盲注时间线/拖库树/SSE 进度局部超越 sqlmap | sqlmap 模式结果闭环断裂、无 CLI/API/用户文档 |

**执行策略**：按 Phase 1（P0，安全与正确性）→ Phase 2（P1，能力补齐）→ Phase 3（P2，锦上添花）分三批执行，每批结束后跑测试回归。

---

## 1. Phase 1 —— P0 修复（安全/正确性/性价比最高，约 14 项）

### 1.1 安全类（最高优先，先修）

| # | 事项 | 内容 | 来源 |
|---|---|---|---|
| P0-S1 | **sessionFile 白名单化** | `scanRoutes.js:38` 的 sessionFile 未经校验透传，`ScanSession.load/_flush` 直接 fs 读写 → 宿主任意文件读写。sanitizeStart 白名单化：仅允许 tmpdir/CWD 下文件名，拒绝绝对路径、`..`、符号链接 | 03-A2 |
| P0-S2 | **并发扫描上限** | ScanManager 加静态 activeScanCount + 上限，超出返回 `ENGINE_BUSY`（错误码已存在），防本地 DoS | 03-A4 |
| P0-S3 | **配置全量白名单 + clamp** | 废弃 `...cfg` 盲展开，逐字段收编：extractConcurrency(1~16)、dumpMaxRows(≤50000)、timeBlindSamples(3~10)、jitterMs(0~5000)、maxColumnsGuess(1~100)、blindRobust.*、dumpRowLimit(1~1000) | 03-A5 |
| P0-S4 | **利用页移除硬编码 authorized** | `ExploitPage.buildTarget` 硬编码 `authorized:true` → 改为携带用户勾选态 | 04-S18 |

### 1.2 正确性类（检测召回）

| # | 事项 | 内容 | 来源 |
|---|---|---|---|
| P0-D1 | **补数字型上下文 payload** | payloads.js 每库每技术增加无引号变体（`{ORIG} AND 1=1/1=2`、数值型 error），各检测器开头加一次"数值上下文探测"；修复 `id=1` 数字参数三技术漏检 | 01-建议1 |
| P0-D2 | **UNION 列 CAST 兼容** | discoverEchoColumns/UnionDetector/DBFingerprinter 标记列改用 CAST(...AS CHAR/NVARCHAR)，修复 MSSQL/Oracle/PG 严格类型漏检 | 01-建议2 |
| P0-D3 | **提取/指纹标记对 tamper 免疫** | Extractor:234 / DBFingerprinter:114 / InlineQueryDetector:45 标记匹配改大小写/编码不敏感；applyTampers 前对 `__S__/__E__` 占位暂存-还原；修复开 tamper 后拖库静默失效 | 01-建议3 |

### 1.3 性能类（数量级收益）

| # | 事项 | 内容 | 来源 |
|---|---|---|---|
| P0-P1 | **限速治理（合并）** | ① 前端限速配置真正生效：HttpClient 支持 ratePerSec 透传 + 按扫描隔离的桶（03-A3，现为写死 defaults.ratePerSec，前端设置恒无效）；② 默认值放开：3 req/s → 如 30~80（02-建议1，单项即 8–20× 提速）；③ 移除 scanRoutes:39 无效 clamp | 03-A3 + 02-建议1 |
| P0-P2 | **指纹/猜列/基线跨点共享** | 每注入点重跑 8-9 请求指纹、columnGuess 被指纹/Union 各跑 6 次、检测器各自重测 baseline → 缓存跨点共享，省 1/3 请求 | 02-建议2 |
| P0-P3 | **ErrorDetector 全库遍历截断** | dbms 未知时 42 连发 → 按高频库顺序 + 命中即停（43→6 请求） | 02-建议3 |

### 1.4 资源生命周期（长跑稳定）

| # | 事项 | 内容 | 来源 |
|---|---|---|---|
| P0-R1 | **扫描上下文回收** | ScanManager 增加 `_retire(scanId)`：completed/stopped/error 后 30s TTL 清 scans.delete + eventBus.dispose；`toSSE` 未知 scanId 补 `res.end()`；scans Map 上限 100 | 03-A1 |

### 1.5 体验类（闭环断裂）

| # | 事项 | 内容 | 来源 |
|---|---|---|---|
| P0-U1 | **sqlmap 模式结果闭环** | useEvents 在 scan_completed(engine=sqlmap) 调用 `/sqlmap/:id/report` 包装为可渲染视图 + saveScanToHistory；ReportPage/useScan 按引擎路由 | 04-S1 |
| P0-U2 | **sqlmap 参数透传** | SqlmapConfig 增加 proxy/timeoutMs/retry/randomUA + UI + startScan 透传；内置面板的代理/认证/超时/重试在 sqlmap 模式复用 | 04-S2 |

---

## 2. Phase 2 —— P1 修复（能力补齐，约 24 项）

### 2.1 检测能力（5 项）
- P1-D1 **boundary 闭合探测**：检测前对原值追加 `'`/`')`/`"))`/`"` 基线对比识别闭合上下文，写入 point.boundary 供各检测器选前缀后缀（M）
- P1-D2 **时间盲注提取通道**：Extractor.extractTime 与 extractBoolean 同构，判定用响应耗时 ≥ 阈值；ScanManager 按技术路由（M）
- P1-D3 **增强 DB 指纹**：ERROR_SIG 拆 per-dbms 报错签名表 + 时间向量定库；dbms=null 时遍历库模板而非死回退 MySQL（M）
- P1-D4 **响应相似度升级**：_similar 从 LCP 升级为分块比对 + 动态内容块排除 + 锚点配置（对标 --string/--not-string）（M）
- P1-D5 **WAF 自动 tamper 重跑**：wafAgg 高置信时自动套 wafRecommend 链对未命中点重跑一轮（节流）（M）

### 2.2 性能（5 项）
- P1-P1 轻量布尔指标：大 body 用状态码/长度优先判定，省 CPU/带宽 50%+（M）
- P1-P2 重试加指数退避 + 快速失败（失败目标 70+→10 请求）（S）
- P1-P3 盲注缓存 LENGTH 与常见值（对标 --predict-output，version 96→2-10 请求）（S）
- P1-P4 提取阶段点间并行 + 与检测重叠（M）
- P1-P5 显式 HTTP Agent + keep-alive 保证（Node 版本无关）（M/L）

### 2.3 架构（6 项）
- P1-A1 日志脱敏 + 报告访问护栏：URL 剥离 user:pass@ 与凭据键、payload 证据截断；报告端点受 token 保护（S）
- P1-A2 core→engine 反向依赖解耦：obfuscatePayload 下沉 core/tamper（S）
- P1-A3 请求构造三份复制收敛为单一 buildInjectionRequest；WRAP 合并单一导出；表单解析抽共用模块（M）
- P1-A4 删除 ReportGenerator.build 死代码；Tauri 导出走 saveFile 桥（S）
- P1-A5 装配与生命周期：index.js 拆 createApp()/start()，路由改工厂注入，SIGINT/SIGTERM 优雅关闭（M）
- P1-A6 关键路径单测：Scheduler.run、HttpClient 超时/重试/桶、eventBus cleanup、sessionFile 校验、ratePerSec 生效回归（M）

### 2.4 体验/文档（8 项）
- P1-U1 sqlmap 模式 status 预检（S）
- P1-U2 漏洞详情补证据：VulnDetail 展示 evidence + 完整请求（M）
- P1-U3 导出格式扩展：CSV（漏洞表+拖库数据两档）、Markdown 可选（M）
- P1-U4 注入点精确指定：Body/Cookie/Header 支持 `"id":"1*"` 标记 → 生成 -p（M）
- P1-U5 CLI 模式：server/bin/cli.js 包装 ScanManager，`sqli-scan` bin（M）
- P1-U6 REST API 文档 docs/api.md（S）
- P1-U7 用户手册 docs/user-guide.md（M）
- P1-U8 日志分级与脱敏：logger 文件日志降为 info + rotation + 敏感键打码；localStorage 不存认证/代理（M）

---

## 3. Phase 3 —— P2 增强（锦上添花，约 20 项，按需认领）

- 检测：补齐 14 个缺失 tamper（xforwardedfor/varnish/hex2char/0eunion 等）+ space2comment 状态机 + randomcase 限关键字；盲注提取重测/投票；level/risk 分级 + OR-based payload；URI 路径注入点/任意位置 `*`（01-建议9~12）
- 性能：会话默认落盘（复扫 0 请求）；参数预筛选（省 50-75%）；CPU 比对下沉；time 盲注参数化（02-建议9~12）
- 架构：前端测试并行挂起修复（fileParallelism:false）；coverage 门禁；清理 nul/.trash/logger.js.bak/engine.log 等遗留物；ESLint + JSDoc 类型检查（03-A12~14）
- 体验：拖库数据单独导出；进度条真实化；HTTP 方法 PUT/PATCH/DELETE；payload 前缀/后缀入口；会话续跑 --resume；一次性免责声明；sqlmap 面板 tamper 动态拉取（04-S7/8/10/11/17/19/20）

---

## 4. 执行分工建议

| 批次 | 建议子代理 | 职责 |
|---|---|---|
| Phase 1 | 子代理 A（安全）：P0-S1~S4 | sessionFile 白名单、并发上限、配置白名单、authorized 移除 |
| Phase 1 | 子代理 B（检测）：P0-D1~D3 | 数字上下文 payload、UNION CAST、标记免疫 |
| Phase 1 | 子代理 C（性能）：P0-P1~P3 + P0-R1 | 限速治理、共享缓存、error 截断、扫描回收 |
| Phase 1 | 子代理 D（前端）：P0-U1~U2 | sqlmap 闭环、参数透传 |
| Phase 2 | 2-3 个子代理按 检测/性能/架构+体验 分组 | 见 Phase 2 清单 |
| Phase 3 | 按需认领 | 见 Phase 3 清单 |

每批完成 → 跑 `server` 测试（node --test）+ 前端 `vitest run`（--no-file-parallelism）回归 → 汇报。

---

## 5. 风险与注意

- 引擎改动会触碰核心检测逻辑，P0-D1/D2 需配套测试防回归
- 限速放开影响对外部目标的礼貌性，默认值取 30 且保留用户可调
- sessionFile 白名单可能影响既有会话恢复功能，需兼容旧格式
- sqlmap 桥（sqlmapRoutes/sqlmapBridge）改动不影响内置引擎路径，可并行
