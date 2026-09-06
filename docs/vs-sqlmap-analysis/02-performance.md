# 性能/速度方向差距分析：sqli-scanner vs sqlmap

> 只读分析，未修改任何项目代码。数据来源：`server/src/` 源码逐行阅读 + sqlmap 官方 Wiki/Usage 调研（WebSearch）。
> 运行环境：Node v22.22.2（`http.globalAgent.keepAlive=true`，`maxSockets=Infinity`）。

---

## 1. 现状梳理（性能相关实现）

### 1.1 调度层 `server/src/services/Scheduler.js`

| 项 | 现状 | 位置 |
|---|---|---|
| 并发池 | 固定游标池 `Math.min(concurrency, items.length)`，worker 自取任务 | `run()` L21-47 |
| 默认并发数 | `concurrency=4`，API 入参 clamp 1–10 | `config/defaults.js` L10；`api/scanRoutes.js` L40 |
| 重试 | 任务级 `retry=2`，**立即重试无退避**，失败仅 warn 不抛 | `run()` L29-40 |
| 限速 | 明确注释"限速由 HttpClient 令牌桶统一负责"，`ratePerSec` 仅保留参数 | L1-13 |

### 1.2 网络层 `server/src/core/httpClient.js`

| 项 | 现状 | 位置 |
|---|---|---|
| 底层库 | axios `^1.7.2`（实测装 1.18.1），http/1.1 | `package.json` |
| 令牌桶 | 全局单桶：`ratePerSec=3`、`capacity=ratePerSec=3`、`tokens=3`，不足 `await setTimeout(waitMs)` 后直接 `tokens=0` | `TokenBucket` L9-34；`defaults.js` L7 |
| 超时 | `timeoutMs=10000`，时间盲注追加 `sleep*1000`=12s | `defaults.js` L5；`TimeBlindDetector.js` L96 |
| 重试 | 请求级 `retry=2`，**网络错误立即重试**；超时(`ECONNABORTED`/timeout)直接抛不再重试 | `request()` L149-173 |
| keep-alive | **未显式配置 agent**，依赖 Node 全局 agent（v22 默认 keepAlive=true）；无 `maxSockets` 显式限制 | `constructor()` L121-127 |
| HTTP/2 | 不支持（axios http1.1） | — |
| 代理 | http/https 走 axios `proxy`；socks5 走 `SocksProxyAgent` | `buildProxyAgent()` L91-106 |
| cookie | 仅透传 `target.cookieParams` 合入请求头，**不维护服务端 Set-Cookie 会话**；表单点 CSRF token 静态携带（仅二阶 refreshCsrf 会刷新） | `mergeAuthHeaders()` L65-81；`Detector.buildRequest` L43-59 |
| WAF 规避 | 随机 UA 池(10 条)、`jitterMs` 随机延时、tamper 链；默认全关 | L37-53、L109-114；`defaults.js` L25-32 |

### 1.3 检测流水线 `server/src/engine/ScanManager.js`

- **每注入点独立做完整指纹**：`DBFingerprinter.fingerprint` 在 `scheduler.run` 的每个 point worker 内执行（L202），baseline/猜列/回显列/版本探测全部重跑，跨点零共享。
- **两层并行调度**（L222-258）：Fast 层 `[union,error,boolean,inline]` 并行；Fast 命中且未选 stacked 时跳过 Slow 层 `[time,stacked,oob]`。
- 检测→提取**串行**：`_run` 内全部点检测完（L193-262）后才进入提取循环（L301-332），点间逐个 `await`。
- 盲注提取仅做 **version 证明**（`extractProof`），不做完整拖库（L308-317）。

### 1.4 检测器请求预算（默认配置，单注入点）

> 前提：`defaults`（techniques=[union,error,boolean,time]，blindRobust.enabled=true），令牌桶 3 req/s。

| 阶段 | 请求数 | 说明 |
|---|---|---|
| DBFingerprinter | **8–9** | 1 baseline + `binaryGuessColumns`(≈log2(50)≈6) + 1 discoverEchoColumns + 1~2 UNION 版本探测 |
| UnionDetector | **8** | 1 baseline + 6 猜列 + 1 UNION marker（**与指纹重复猜列/重复 baseline**） |
| ErrorDetector | **3**（dbms 已知）/ **43**（dbms=null 时遍历全部 14 库×3 模板） | 每模板 1 次，命中再 +1 确认 |
| BooleanBlindDetector | **11 命中** / **17 未命中** | robust 分支：5 基线并发 + 每模板对 3 真+3 假并发；第一对命中即 break |
| TimeBlindDetector | **10** | 5 基线 + 5 注入采样并发，每请求 `SLEEP(2)` |
| **单点合计** | **≈46 干净 / ≈85 dbms 未知 / ≈20 union 命中** | 令牌桶 3/s → 46 请求墙钟 ≥15.3s |

4 参数目标：4×46≈**184 请求**，纯限速墙钟 ≥61s + RTT。日志佐证（`server/engine.log`）：失败目标上单请求连打 3 次（第 1/2/3 次重试）无退避。

### 1.5 盲注二分提取 `server/src/engine/Extractor.js`

- **字节级二分 0–255（8 轮）**：`_binarySearch` L436-459，长度二分用 `LENGTH(expr)>cmp`，字符用 `ASCII(SUBSTRING(...))` 逐字节，UTF-8 由 `TextDecoder` 还原（L416）。
- **多位置并行**：`extractConcurrency=4`（`defaults.js` L20），每轮取 K 个未收敛位置 + **1 个共享 false 基准**（`AND (1=2)`），`_sendBatch` L420-433。
- 请求公式：长度二分 `8×2=16` + 字节提取 `ceil(L/K)×8×(K+1)`。**version(7 字节 MySQL)≈96 请求**。
- 布尔判定：每个探测仅 `trueData !== falseData` 一次比较，无二次确认。

### 1.6 拖库 `Extractor.dumpDatabase/dumpAllDatabases` + `ColumnTypeEnumerator`

- 表级并发 `dumpConcurrency=4`，库级并发 `dumpDatabaseConcurrency=2`（`defaults.js` L21-22）。
- 数据页 `dumpRowLimit=100` 行/请求，`GROUP_CONCAT` 整页带回；`dumpMaxRows=100×50` 全量保护（L270-302）。
- 列类型枚举每表 **+1 请求**，`_colTypeCache` 有表级缓存（`ScanManager.js` L61、L494）。
- 每表请求预算：1(列) + ceil(rows/100)(数据) + 1(类型)；1 库 5 表 100 行/表 ≈ 17 请求。

### 1.7 缓存/会话/去重

| 项 | 现状 | 位置 |
|---|---|---|
| 会话续跑 | `ScanSession` JSON 增量落盘 + resume（对标 sqlmap --session/--resume），**默认不启用**（`sessionFile` 未配置） | `sessionStore.js`；`ScanManager.js` L160-170 |
| 列数缓存 | 仅 `Extractor._guessColumnsCached` 点内缓存（L209-214）；指纹/Union 的猜列结果**未写回 point** | |
| 列类型缓存 | `_colTypeCache`（db.table→types） | `ScanManager.js` L494 |
| 跨点共享 | **无**：dbms 指纹、猜列、echo 列均按 point 重算 | |
| 查询结果缓存 | 无（对标 sqlmap --fresh-queries 的反面：sqlmap 默认缓存查询结果） | |

### 1.8 资源占用 / 事件循环阻塞点

- 单线程 Node；检测、相似度计算全部主线程。
- 大正则：`ERROR_SIG` 对超长 body 多次 `.match()`（`payloads.js` L430）。
- `BooleanBlindDetector._similar` 做最长公共前缀字符循环（L241-250），每个样本与 5 个 baseline 各比一次；`_isMeaningfulDiff` 对每对做 `\s+` 正则替换生成副本（L228-233）；`baselineNoiseRate` 两两比较 C(5,2)=10 次（`statsHelper.js` L51-62）。body 超 100KB 时每请求 CPU 数十毫秒级。
- axios 自动 `JSON.parse` 再 `String(r.data)` 转回，大响应双份内存占用。

---

## 2. 与 sqlmap 差距清单

> sqlmap 基准参数：`--threads` 默认 1、`--delay` 默认 0（无限速）、`--timeout` 默认 30s、`--retries` 默认 3；优化类：`-o/--optimize`（含 `--predict-output`、`--keep-alive` 等启发式开关）、`--null-connection`（仅取页面长度）、`--fresh-queries`（强制重查）、`--session/--resume`（会话续跑）、`--skip-static`/`--smart`（启发式跳过）；盲注：bisection 每 ASCII 字符约 **7** 个请求，Huffman 编码可进一步压缩常见字符。

### 差距 1：全局令牌桶 3 req/s 锁死吞吐（最大差距）

- **sqlmap**：`--delay=0` 默认无限速，`--threads=N` 下吞吐由网络/RTT 决定；RTT 50ms 时单线程理论 ~20 req/s。
- **本项目现状**：`defaults.ratePerSec=3`、`TokenBucket.capacity=3`（`httpClient.js` L13-18），全局唯一桶。并发池=4 形同虚设——4 个 worker 全在 `acquire()` 排队。
- **影响**：干净目标单点 46 请求被压到 ≥15.3s；184 请求(4 参数) ≥61s。**速度被限速器本身锁死**，其余优化收益全被 3 req/s 吞掉。量化：限速开启后吞吐 = min(并发×1/RTT, 3) 恒等于 3。

### 差距 2：每注入点重复完整指纹 + 重复猜列（请求浪费大户）

- **sqlmap**：DBMS 指纹整站做一次；多参数时对其他参数做 **redundancy check**（1–2 个请求快速排除非注入参数），`--skip-static` 跳过静态参数。
- **本项目现状**：`ScanManager._run` 每个 point 都调 `DBFingerprinter.fingerprint`（8–9 请求）；同点内 UnionDetector 再猜列 6 次（`columnGuess.js` binaryGuessColumns），与指纹猜列完全重复；`discoverEchoColumns`(1) 与 UnionDetector UNION marker(1) 也重复；各检测器 baseline 相互独立（fingerprint/union/error 各 1 次，boolean/time 各 5 次）。
- **影响**：4 参数目标仅指纹+猜列浪费 ≈ 4×9 + 4×6 ≈ **60 请求**（约占总量 1/3），纯属重复劳动。假设 RTT=100ms 且无限速，省掉即省 ~6s。

### 差距 3：dbms 未知时 ErrorDetector 全库暴力（请求爆炸）

- **sqlmap**：指纹失败时按 `--dbms` 显式指定或按技术从**最常用库优先**顺序试探，通常 ≤3–5 个错误 payload。
- **本项目现状**：`ErrorDetector.detect` L31-33，`dbms` 为 null 时 `Object.values(PAYLOADS).flatMap(t=>t.error)`，**遍历 14 个库 × 3 模板 = 42 次** + baseline，每个命中还 +1 确认。
- **影响**：指纹识别失败的目标（占真实目标相当比例），单点 error 阶段请求数从 3 → 43，**×14 倍**；且被令牌桶进一步放大到 ≥14.3s 纯等待。

### 差距 4：布尔盲注判定无 `--null-connection` 等价（带宽/CPU 浪费）

- **sqlmap**：`--null-connection` 只取 `Content-Length`/status 判断 true/false，不下载 body；`--predict-output` 缓存/预测常见查询结果。
- **本项目现状**：`BooleanBlindDetector._similarToBaseline` 每次下载完整 body 并与 5 个 baseline 做前缀字符扫描；`_isMeaningfulDiff` 正则替换全文。`Extractor.extractBoolean` 每个探测也全量取 body。
- **影响**：百 KB 级响应目标，盲注请求带宽 ×N、每次判定 CPU 数十 ms；大数据拖库场景（`GROUP_CONCAT` 整页）body 随行数线性膨胀，重复下载浪费显著。

### 差距 5：time 盲注固定 `SLEEP(2)` 且无提前终止

- **sqlmap**：`--time-sec` 可调，时间盲注同样慢但可调参；检测器可复用已确认延迟缩短探测。
- **本项目现状**：`TimeBlindDetector` sleep 硬编码 2（L92），基线 5 + 注入 5 采样；注入响应必须等满 sleep 才能判定；5 次采样全部发完整 SLEEP。
- **影响**：单点 time 阶段墙钟 ≥2s（并发采样）但请求等待时间 = 10×(2s+RTT)；多目标累计拖慢。对真实慢目标（基线本身 >2s）判定还会失效，需重试。

### 差距 6：盲注二分 8-bit vs sqlmap 7-bit + Huffman

- **sqlmap**：纯 ASCII 字符 **7 次二分请求/字符**；非 ASCII 自适应扩范围；拖库时 Huffman 编码把高频字符压到更少请求。
- **本项目现状**：`_binarySearch` 0–255 字节级固定 8 轮/字节；无常见值/常见长度缓存（`LENGTH` 结果不缓存）。
- **影响**：ASCII 场景 8/7 ≈ **+14%** 请求；每轮还固定发 1 个 false 基准，对 `extractConcurrency=4` 有 20% 的基准开销，但多位置并行抵消了大部分差距。整体盲注提取请求数：本项目 version(7B)≈96 vs sqlmap≈55（单线程），差 ~1.7×（主要来自 8-bit + 长度二分 + 无 predict）。

### 差距 7：重试无退避 + 失败目标放大请求

- **sqlmap**：`--retries=3` 对连接类错误重试，有基础退避/超时控制。
- **本项目现状**：`Scheduler.run`（L29-40）与 `HttpClient.request`（L149-173）均**立即重试**；且 `ECONNREFUSED`/超时在 HttpClient 层超时直接抛（不再重试），但 Scheduler 层会整点重试（每个点每检测器又重跑）。
- **影响**：不可达目标：每请求打 3 次（engine.log 实证），4 点 × 6 检测器 × 3 ≈ **70+ 无效请求**；且无退避在服务器过载时加剧拥塞。

### 差距 8：会话/缓存默认关闭，同目标重扫全量重测

- **sqlmap**：默认写会话（--output-dir 保存数据），`--resume` 续跑；查询结果有缓存，`--fresh-queries` 才强制重查；`--session` 保存 HTTP 会话。
- **本项目现状**：`ScanSession` 仅当 `config.sessionFile` 提供时启用（`ScanManager.js` L160），默认关；无跨扫描结果缓存。
- **影响**：二次扫描（改一个参数/复测）请求 100% 重放。缓解成本低，收益直观。

### 差距 9：HTTP 连接管理非显式（keep-alive 依赖 Node 版本）

- **sqlmap**：`--keep-alive` 显式开关，连接池大小受 `--threads` 控制。
- **本项目现状**：axios 未传 `httpAgent/httpsAgent`，依赖 Node 全局 agent——v22 实测 `keepAlive=true`，但 Node 18 默认 `keepAlive=false`；且 `maxSockets=Infinity` 无上限（当前并发 ≤10 尚无风险）。
- **影响**：Node 18 下每请求新建 TCP 连接，RTT=100ms 时 3 req/s 限速下握手开销占比大；版本迁移后行为漂移不可控。

### 差距 10：检测与提取串行、点间不并发

- **sqlmap**：检测到某参数即开始该参数数据提取，且 dump 阶段 `--threads` 对逐字符二分并行。
- **本项目现状**：`_run` 先全点检测（L193-262）再逐点提取（L301-332），点间串行；提取内部库/表级并发受 2/4 限制且被令牌桶 3/s 压死。
- **影响**：慢目标多参数时，"先等全部检测完再拖库"比"边测边拖"墙钟更长；拖库吞吐 = 3 req/s 时 100 表 × 4 请求/表 = 400 请求 ≥133s。

### 差距 11：无启发式剪枝（--skip-static / --smart 等价物）

- **sqlmap**：`--skip-static` 跳过静态参数（值不随请求变化的参数），`--smart` 仅对启发式判定"可能有注入"的参数深测。
- **本项目现状**：`TargetParser.discover` 对 URL/Body/Cookie/Header 全部参数无差别建点（`TargetParser.js` L36-61），无预筛选、无参数去重。
- **影响**：`?a=1&b=1&c=1&d=1` 4 个相同语义参数全部满额检测，浪费 75% 请求。

### 差距 12：内存/CPU 细节

- body 重复字符串化 + 正则替换 + 前缀扫描（见 1.8），大响应 JSON 双解。
- sqlmap 为 C 级/Python 多线程且对响应仅做长度/指纹，CPU 密集度低。
- 本项目单线程下，超大 body + 5 baseline 相似度计算可阻塞事件循环（SSE 推送、其它扫描响应全部卡顿）。

---

## 3. 优化建议

### 建议 1（P0，S）：限速默认放开或大幅调高
- **内容**：`defaults.js` L7 `ratePerSec` 默认改 0（不限速）或 ≥20（API clamp 上限已是 20，见 `scanRoutes.js` L39）；`TokenBucket.capacity` 改 `ratePerSec`（或无速时跳过 acquire）；前端默认配置同步改。
- **预期影响**：吞吐从 3 req/s → RTT 决定（50ms RTT 下 4 并发 ≈80 req/s），单点 46 请求墙钟 15.3s→~2s，**整体提速 ~8–20×**。风险：目标/WAF 压力增大，需保留显式开关让安全场景 opt-in 限速。
- **工作量**：S。**优先级**：P0。

### 建议 2（P0，M）：指纹/猜列/基线跨点共享
- **内容**：
  a. `ScanManager._run` 中 dbms 指纹只做一次（首个 point 完成后 `point.dbms/ctx.dbms` 传播给其余 point），后续 point 跳过 `fp.fingerprint` 的猜列与版本段（保留 1 次 baseline 用于 WAF）。
  b. `binaryGuessColumns` 结果写回 `point.columns`，`UnionDetector`/`DBFingerprinter` 复用（现仅 `Extractor._guessColumnsCached` 有缓存）。
  c. `discoverEchoColumns` 结果写回 `point.echoCols`，避免 UnionDetector 与指纹重复定位。
- **预期影响**：4 参数目标省 ~60 请求（占 1/3），单点指纹 8–9 → ~1–2；同点猜列 6+6 → 6。
- **工作量**：M（涉及 ScanManager 上下文传播与三处调用点）。**优先级**：P0。

### 建议 3（P0，S）：ErrorDetector 全库遍历截断
- **内容**：`ErrorDetector.js` L33 改为按 `SUPPORTED` 顺序（MySQL→PostgreSQL→SQL Server→Oracle→...）逐库试探，命中即停；每个库内模板命中即 break；加总请求上限（如 ≤6）防止 42 连发。
- **预期影响**：dbms 未知目标 error 阶段 43 → ≤6 请求（×7 节省）；命中目标 2–4 请求。
- **工作量**：S。**优先级**：P0。

### 建议 4（P1，M）：布尔判定走"轻量指标"优先
- **内容**：`BooleanBlindDetector._similar` 前先比较 `Content-Length` 与 status（axios 响应自带），**长度差即判不同则跳过 body 下载后的全文扫描**；`_isMeaningfulDiff` 的 `\s+` 替换改为先查长度差 >1 短路。可选：对标 `--null-connection`，布尔探测请求用 `HEAD`/截断 body（axios `responseType:'stream'` + 只读前 N 字节）获取长度。
- **预期影响**：大 body 目标判定 CPU 从 O(5×L) 降到 O(1)（长度即分）；带宽省 50%+；盲注提取阶段同样受益。
- **工作量**：M。**优先级**：P1。

### 建议 5（P1，S）：重试加指数退避 + 快速失败
- **内容**：`HttpClient.request` L149 与 `Scheduler.run` L29 重试间隔改为 `min(200ms×2^attempt, 2s)`；连接错误（ECONNREFUSED/ECONNRESET）连续 N 次失败后对该点/检测器直接放弃（对标 sqlmap 对不可达目标快速终止）。
- **预期影响**：不可达目标无效请求 70+ → ~10；过载目标避免拥塞加剧。
- **工作量**：S。**优先级**：P1。

### 建议 6（P1，S）：盲注二分缓存 LENGTH 与常见值
- **内容**：`Extractor.extractBoolean` 的 `LENGTH` 结果缓存（同一表达式只测一次）；对标 `--predict-output`：对 version()/database() 等常见查询加"先试常见值"前缀（如 version 常见 `8.0.x`、`5.7.x` 直接整串比对），命中即省全部二分。
- **预期影响**：version 提取 96 → 2–10 请求（常见值命中）；常规场景省长度二分 16 请求。
- **工作量**：S。**优先级**：P1。

### 建议 7（P1，M）：提取阶段点间并行 + 与检测重叠
- **内容**：`ScanManager._run` 提取循环（L301-332）改为 `Promise.all` 按 `extractConcurrency` 池化；或检测命中即触发该点提取（不等待全点检测完）。注意与 `_mergeExtracted` 的竞态（可用互斥/按点独立对象后合并）。
- **预期影响**：多注入点拖库墙钟从串行累加 → max(单点)；慢目标收益显著。
- **工作量**：M。**优先级**：P1。

### 建议 8（P1，M）：显式 HTTP Agent + HTTP/2
- **内容**：`HttpClient` 构造 `http.Agent({keepAlive:true, maxSockets: concurrency, timeout: 10000})` / `https.Agent` 显式注入；评估 `http2-wrapper` 支持 HTTP/2（对标 sqlmap 实验性 http2）。
- **预期影响**：Node 18 兼容性确定；`maxSockets` 与 Scheduler 并发对齐，避免连接数失控。
- **工作量**：M（HTTP/2 为 L）。**优先级**：P1（agent 部分）/P2（HTTP/2）。

### 建议 9（P2，S）：默认开启会话落盘
- **内容**：`ScanManager` 无 `sessionFile` 时自动落到 `logs/sessions/<scanId>.json`（`logs/` 已存在），报告页提供"续跑"入口；保留 `--fresh-queries` 语义（可选强制重测）。
- **预期影响**：二次扫描/中断续跑请求量 →0（已完成点跳过），对标 sqlmap --resume。
- **工作量**：S。**优先级**：P2。

### 建议 10（P2，S）：参数预筛选
- **内容**：`TargetParser.discover` 对值相同的参数去重（同一 URL 重复参数只测一次）；对标 `--skip-static`：对首个参数发 1 次基线后，对后续参数比对原始响应是否与已测参数一致，一致则跳测。
- **预期影响**：多参数目标省 50–75% 检测请求。
- **工作量**：S。**优先级**：P2。

### 建议 11（P2，L）：CPU 密集比对下沉/减负
- **内容**：`_similar`/`baselineNoiseRate`/`_isMeaningfulDiff` 用 `Buffer` 比较或抽样前缀（前 1KB）替代全量字符循环；超大 body 的 `ERROR_SIG` 正则先长度/采样限流。
- **预期影响**：百 KB 级响应下事件循环卡顿消除，SSE 推送与并发扫描不互相阻塞。
- **工作量**：L。**优先级**：P2。

### 建议 12（P2，M）：time 盲注参数化与加速
- **内容**：`TimeBlindDetector` sleep 改为 `config.timeBlindSleepSec`（默认 2，可调），`--time-sec` 对标；注入采样对已确认延迟的请求可跳过后续采样（`stableRatio` 达阈值提前 break）。
- **预期影响**：慢目标/低延迟目标适配；命中目标 time 阶段从 10 请求压到 5–7。
- **工作量**：M。**优先级**：P2。

### 建议汇总表

| # | 建议 | 优先级 | 工作量 | 预期收益 |
|---|---|---|---|---|
| 1 | 限速默认放开 | P0 | S | 吞吐 3→80 req/s，整体 8–20× |
| 2 | 指纹/猜列/基线共享 | P0 | M | 4 参数省 ~60 请求（1/3） |
| 3 | ErrorDetector 截断 | P0 | S | dbms 未知目标 43→6 请求 |
| 4 | 轻量布尔指标 | P1 | M | 大 body CPU/带宽 50%+ |
| 5 | 重试退避+快速失败 | P1 | S | 失败目标 70+→10 请求 |
| 6 | 盲注缓存+预测值 | P1 | S | version 96→2–10 请求 |
| 7 | 提取点间并行 | P1 | M | 多库拖库墙钟→max(单点) |
| 8 | 显式 agent/HTTP2 | P1 | M/L | 连接确定性 |
| 9 | 会话默认落盘 | P2 | S | 复扫 0 请求 |
| 10 | 参数预筛选 | P2 | S | 多参数省 50–75% |
| 11 | CPU 比对减负 | P2 | L | 事件循环不阻塞 |
| 12 | time 参数化 | P2 | M | 时间盲注适配性 |

---

## 核心结论

1. **最大瓶颈是全局令牌桶 3 req/s**（`defaults.ratePerSec=3`），它把并发池、多字符并行等所有提速手段的收益全部吞掉；放开限速是收益最高的单项改动（8–20×）。
2. **第二大头是重复劳动**：每注入点重跑 8–9 请求指纹、同点猜列重复、dbms 未知时 error 全库 42 连发、检测器各自重测 baseline——仅去重即可省 1/3 请求。
3. 盲注二分（字节级 8 轮 + 多位置并发）结构上已接近 sqlmap（每 ASCII 字符 7 请求），差距主要是缺 `--predict-output` 常见值缓存、`--null-connection` 轻量判定与 `--skip-static` 参数剪枝。
4. 会话/resume 能力已具备但默认关闭，重试无退避、keep-alive 依赖 Node 版本、检测/提取串行等属于中优先级工程化问题。
5. 建议按 P0（限速放开→指纹共享→error 截断）先行落地，即可在不动架构的前提下获得数量级的速度提升。
