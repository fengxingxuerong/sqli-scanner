# sqli-scanner 检测引擎深度审查报告（02-engine）

> 审查日期：2026-08-25 · 分支 master @ a3ef37b · 审查人：安全引擎/Node.js 架构审查（ox-alpha）
>
> 已确认基线（主代理）：`Detector` 基类含 probeBoundary 并发探测 / sendConcurrent 受控并发池 / `__networkMs` 网络计时语义；`ScanManager` 门面模式 + `_mapPool`；`httpClient` SSRF 分层防护 + DNS 钉死 + 令牌桶限速。本次在此基础上补齐七项深度审查：① 9 个 detector 逐个审读（布尔基准线 / blindRobust 时间采样统计 / columnGuess 二分收敛的误报漏报边界）；② Extractor / extractScope / ColumnTypeEnumerator 盲注提取请求量估算与 dumpMaxRows/dumpRowLimit 内存兜底验证；③ Exploiter os-shell/file-write 多方言 SQL 拼接构造正确性；④ scanRunner/crawler/TargetParser/DBFingerprinter 并发生命周期与取消传播；⑤ sessionStore 原子写与损坏容错；⑥ 死代码与未用导出扫描；⑦ 疑似 bug 独立列节。
>
> 条目格式：`[文件:行号 严重级别]`。严重级别：高（正确性/误报漏报/安全一致性）、中（可感知性能损失/边界缺陷/维护风险）、低（代码质量/一致性）。

---

## 一、9 个 detector 逐个审读（detectors/*.js + Detector.js）

### 1.1 Detector.js（基类）

- [server/src/engine/Detector.js:57-78 中] **probeBoundary 在锚点模式下失去区分能力**：`_boundarySimilar`（L381-386）先走 `matchAnchors`，只要 config 配置了 matchString/notString，对**任意**闭合候选都返回同一锚点判定结果（真页含锚点 → anchored=true）。candidates 按序首个 fulfilled 即命中 → 恒命中空串前缀 `''`，后续 `'`/`')` 等正确闭合前缀永远轮不到。结果：显式配置 --string 类指标的目标上，字符串上下文注入点的 boundary 恒为空，下游布尔/UNION/提取全部按数值上下文构造 payload → 系统性漏报。锚点模式下应改为「真探针含锚点且语法错误对照不含」的双态判据，或直接跳过锚点走相似度分支。
- [server/src/engine/Detector.js:63 低] `point._baselineTitle` 赋值后全仓库无任何读取（`matchTitle` 判定用的是真/假响应各自的 `<title>`，而非此基线学习值）——死赋值，见 §六。
- [server/src/engine/Detector.js:65-71 低] probeBoundary 的 8 个候选并发探测不受 rb.concurrency 等限流参数约束（直接 Promise.allSettled），仅靠 HttpClient 令牌桶兜底；对严格限速目标会一次性排 8 个请求的队。可接受但值得知晓。
- [server/src/engine/Detector.js:423-443 ✓] sendConcurrent 实现：单线程事件循环下 `cursor++` 取号无竞态；out[i] 保序；单个失败置 `__error` 不中断整体；limit 与请求数取 min。语义正确。`__elapsed` 优先取 `__networkMs`、mock 回退总耗时的兼容写法与注释一致。

### 1.2 BooleanBlindDetector（布尔基准线 / blindRobust 统计）

- 判定主逻辑核对结论：legacy 与 robust 均要求「真≈基线 且 假≠基线 且 真假有实质差异」三条件同时成立（L196-215 / L338-356），方向正确，误报控制优于单条件；boundary 感知数字对优先、risk>=2 才投放 OR 对，请求预算有界。
- [server/src/engine/detectors/BooleanBlindDetector.js:498-513 中] **大 body「首尾采样」近似判定引入漏报边界**：`_similar` 在任一串 >64KB 时只比对头部 256 字节 +（仅等长时）尾部 256 字节即判相似。模板化页面（头尾是公共布局/页脚）真条件必然"相似"成立没问题，但**假条件**若与基线长度差在容差内（`max(24, lb*0.12)` 对 100KB 页面是 12KB 容差），中段数据区完全不同也判相似 → `!similarToBaseline(fBody)` 不成立 → 整点漏报。等长才比尾部的写法进一步放宽。建议大 body 也做分块 hash 兜底（chunkSimilarity 已有现成实现）。
- [server/src/engine/detectors/BooleanBlindDetector.js:336 低] 统计显著性检验的对照样本量口径不一致：`twoProportionZ(falseRatio, effSamples, baselineNoiseRateVal, baselines.length)` 把 nB 传成基线**条数**（如 3），而 baselineNoiseRate 的分母实为 C(n,2) 配对数（如 3）。nB 被低估 → SE 偏大 → z 偏小 → 更保守（误报更少、抖动目标漏报略增）。方向安全但统计语义不严格。
- [server/src/engine/detectors/BooleanBlindDetector.js:467-481 ✓] `_isMeaningfulDiff` 零分配流式空白等价比对逐字符核对无误；`_lengthDiffer` 容差与 `_similar` 同参（min 侧 12%）一致。

### 1.3 TimeBlindDetector（时间采样统计判定 blindRobust）

- [server/src/engine/detectors/TimeBlindDetector.js:186-241 ✓] robust 主路径核对：阈值取 `max(μ+z·σ, μ+adaptiveFloor)`，σ=0 时退化为 μ+absFloor ≡ legacy；注入采样用 sendConcurrent + `__networkMs`（不含令牌桶排队），计时语义与基线修复一致；stableRatio ≥ minStableRatio 才确认。判定链完整。
- [server/src/engine/detectors/TimeBlindDetector.js:42-46 中] **dbms 未知时的定库遍历墙钟成本**：按 TIME_DBMS_ORDER 串行对最多 5 个库各跑一遍 `_detectOne`（每库 baselineSamples + samples 次 × sleep 秒延迟）。默认配置下最坏 5 库 × (4+4) × 2s ≈ 80s+ 纯 sleep 墙钟，且此路径在 Scheduler 单 point worker 内串行。建议未知库场景先用时间指纹命中一个候选再进入完整检测（DBFingerprinter 已有时间向量通道，结果未传递复用）。
- [server/src/engine/detectors/TimeBlindDetector.js:131-141 低] legacy 路径基线与注入都用 `Date.now()` 包裹 `this.send` 总耗时（未传 networkTiming）：限速低时令牌桶排队会计入 elapsed。因基线同法测量可部分抵消，且默认走 robust 路径，风险有限；与 Detector.js L413-416 描述的已修复语义不一致属历史遗留分支。
- [server/src/engine/detectors/TimeBlindDetector.js:278-336 低] _extendedRound 判定放宽为 `ceil(3/2)=2/3` 连续延迟即确认（主路径要求稳定率门槛），level≥2 门控下可接受，但证据串应注明"弱判定"。

### 1.4 UnionDetector + columnGuess.js（UNION 列数二分收敛）

- [server/src/engine/columnGuess.js:18-34 中] **二分判据的单调性假设在 200 状态错误页下失效**：`status>=500 || len < baseLen*0.5` 视为超出列数。大量应用 ORDER BY 越界时返回 200 + 自定义错误页（长度可能与正常页相当甚至更长）→ 所有 mid 都判"成功" → ans=maxCols(50) → 后续 UNION SELECT 50 列必失败 → 静默漏报（无任何 evidence）。建议增加「错误签名对照」或回退线性小步扫描兜底。
- [server/src/engine/UnionDetector.js:49-93 高→中] **存在性门控的漏报边界**：门控要求真假探针互相不相似。对「真/假返回同一模板、仅数据区几字节不同」的目标（搜索页 0 结果 vs 1 结果、列表页空/非空），字符级差异率 <15% 容差 → 门控拒绝 → UNION 能力被跳过。这是防反射误报的必要代价，但对真实 UNION 点构成系统性漏报方向；建议门控拒绝时降级输出 trace 供 level≥2 重试而非直接 return。
- [server/src/engine/UnionDetector.js:112-115 中] **UNION 标记 payload 未补伪表 FROM 子句**：`{ORIG} UNION SELECT 'SQLISCANNER0',...` 无 `FROM dual`（Oracle/DM8）、无 `FROM SYSIBM.SYSDUMMY1`（DB2/Derby）——Extractor.extractScalar（L447-452 fromDummy）和 DBFingerprinter（L121-123）都补了，唯独 UnionDetector 没有 → Oracle/DB2 系目标 UNION 回显定位恒失败（漏报）。DBFingerprinter 能定库却不能定位回显列，能力链条断裂。
- [server/src/engine/UnionDetector.js:27-36 低] 门控相似判定用字符级差异率（比 LCP 抗中段单字符差异），注释与实现对；但 15% 差异率阈值对短响应（<200B）过严，短页面真分化可能不足 30 字节差异被拒。

### 1.5 ErrorDetector

- [server/src/engine/detectors/ErrorDetector.js:20-28 ✓] 基线剔除思路正确：先确认原始请求是否本就含报错特征；命中后二次发送确认稳定性（L91-95），过滤偶发噪声。
- [server/src/engine/detectors/ErrorDetector.js:89-90 低] 基线剔除用 `match[0] === baseMatch[0]` **整串相等**比较：页面固有报错若含变化内容（如表名/路径随参数变化），注入触发的同类型错误签名串不同 → 绕过基线剔除 → 误报。建议按 ERROR_SIG 的库归属分组比较（同类即剔除）而非全等。
- [server/src/engine/detectors/ErrorDetector.js:107-124 低] pickErrorTemplates 按 dbms 名去重，但 PAYLOADS.MariaDB/TiDB 与 MySQL 模板内容相同（协议兼容复用），ORDER 表里 MariaDB→MySQL 相邻两条会投出**完全相同**的模板两次（第二次必同样结果，纯浪费 2 个请求）。

### 1.6 StackedDetector

- [server/src/engine/detectors/StackedDetector.js:79-86 高] **疑似 bug：判定无基线补偿，慢目标系统性误报 Critical**。与注释"与 TimeBlindDetector 保持一致"不符：TimeBlind 用 `基线均值 + 阈值` 判定，Stacked 直接 `elapsed >= thresholdMs`（defaults.timeThresholdMs 固定值）。目标正常响应耗时本身 ≥ thresholdMs（慢站/大页面/跨境 RTT）时，所有采样都计为 delayed → `stable >= ceil(samples/2)` 必然满足 → 未注入点被确认为堆叠注入且定级 **Critical**（scanRunner L331-334 对 stacked 强制 Critical 并压制其它技术证据）。这是全部检测器中误报后果最重的一条。修复：像 TimeBlind 一样先测 N 次基线均值再判 `elapsed >= baseMean + threshold`。
- [server/src/engine/detectors/StackedDetector.js:66-68 低] 采样循环 `templates[i % templates.length]` 轮换不同 payload 模板：确认样本混合多模板，evidence 无法归因到单条 payload；建议固定首模板采样。

### 1.7 InlineQueryDetector

- [server/src/engine/detectors/InlineQueryDetector.js:44-49 高] **疑似 bug：无反射门控 → 回显参数目标必然误报**。命中条件是「test 响应含标记 && base 不含」。对任何把参数值原样回显的页面（搜索框、评论区、echo 参数），test 注入串 `${orig}' || (SELECT '__S__INL__E__') || '` 本身含字面标记 → 被原样反射进响应 → includes 命中 → vulnerable=true。UnionDetector 为同样的反射问题专门做了 `_gateInjection`（真假探针互比），InlineQueryDetector 完全没有等价防护，也没有像 ErrorDetector 那样验证「子查询求值语义」（如比对 `(SELECT 'MARK')` 与 `(SELECT 'OTHER')` 回显差异）。建议：① 复用 UnionDetector 门控；② 或追加第二探针换标记值，两次回显不同才确认。
- [server/src/engine/detectors/InlineQueryDetector.js:77-84 低] 数值型分支直接把值替换为 `(SELECT ...)`，若参数实际处于字符串上下文（引号包裹）则语法错误静默落空——可接受（还有字符型分支），但 boundary 探测结果未用于选择分支。
- [server/src/engine/detectors/InlineQueryDetector.js:97 低] MySQL 用 `||` 串接依赖 ANSI 模式（注释已诚实声明）；MariaDB 默认非 ANSI → MariaDB 字符型内联检测实际不可用，属已知边界而非 bug。

### 1.8 OobDetector / SecondOrderDetector / NoSqlInjectionDetector

- [server/src/engine/detectors/OobDetector.js:26-28 ✓] oob 未启动抛 OOB_DISABLED 由调度层捕获，防御完整；HTTP/DNS 两轮均不做 tamper（会破坏回调地址）的理由成立。
- [server/src/engine/detectors/OobDetector.js:73 低] `waitForToken(token, timeoutMs)` 在 Scheduler worker 内同步阻塞至超时（默认 5s × 2 轮），叠加 DNS 轮时该点墙钟 +10s；stop() 后该等待**不会提前返回**（见 §四 取消传播）。
- [server/src/engine/detectors/SecondOrderDetector.js:51-87 ✓] 三态判定（基线无/实验有/阴性无）逻辑严谨；阴性对照默认关闭时的置信下降已在结构上体现。_store 真实写请求的授权边界由 so.enabled 门控兜底，直达 detect 时抛 SECOND_ORDER_DISABLED 防御到位。
- [server/src/engine/detectors/NoSqlInjectionDetector.js:128-130 中] NoSQL payload 固定为 `${orig}', ${op}]};//` 形态——只适配「JSON body 中字符串值的闭合」场景；URL query 参数注入时该串是无效语法，真阳性（如 PHP Mongo 驱动 URL 参数运算符注入）反而测不出来。当前只覆盖一种入口形态，报告应注明覆盖边界。
- [server/src/engine/detectors/NoSqlInjectionDetector.js:116-125 低] GraphQL 探测经 buildRequest 把查询语句放进**单个参数值**位置，而 GraphQL 端点通常要求整个 body 为 JSON `{query:...}`——除恰好参数名就是 query 且 body 是表单编码的场景外基本打不中。探测有效性存疑但无害。

## 二、Extractor / extractScope / ColumnTypeEnumerator

### 2.1 盲注提取字节级请求量估算（extractBoolean）

判定通道：`{base} AND (ASCII(SUBSTRING(expr,pos,1)) > mid)-- -`，响应 ≠ false 基准即"真"。单值（长度 L 字符）请求量分解：

| 阶段 | 请求数 | 说明 |
|---|---|---|
| 长度二分 `_binarySearch` | ≈8 | hi=255 起 log2，收敛 L |
| 每字符·字符类探测 | 1~2 | cls-digits [48,57] → cls-lower [97,122] → 全区间回退 |
| 每字符·区间二分 | ≤8 | 收窄后 3-4 次；全区间最坏 8 次 |
| 每字符·等值验证 | +1 | extractVerify 默认开 |
| 整值复验 | +1 | P2-P7 投票复验 |
| 失败重试 | 每字节≤3 | 网络失败/验证失败重置二分 |

**总量公式：N ≈ 8 + L × (6~11) + 1**。例：`version()` 10 字节 ≈ 70~120 请求；16 字节 user() ≈ 105~185 请求。K=extractConcurrency(默认4) 并发下墙钟 ≈ N/K × RTT。对照 sqlmap --predict-output 同量级，估算合理。**注意**：该通道仅用于版本证明类短标量（scanRunner §4 只对 boolean/time 技术取 proof），不做整表拖库——若未来开放盲注 dump，L=100KB 表将产生 ~10⁶ 请求，必须在入口硬拦。

### 2.2 dumpData 上限与内存兜底核查

- [server/src/engine/Extractor.js:501 中] **dumpMaxRows 默认值与 lim 联动，非绝对兜底**：`maxRows = ctx.config?.dumpMaxRows ?? lim * 50`，而 `lim = limit ?? config.dumpRowLimit ?? 100`。用户配 dumpRowLimit=50000 时 maxRows 自动放大到 250 万行对象——内存上界实际由用户单参数决定。建议 maxRows 设独立绝对硬上限（如 10⁵），超出时截断并在 meta 标注。
- [server/src/engine/Extractor.js:521-523 中] **疑似 bug：空行过滤导致提前终止**。末页判据 `rowStrs.length < lim` 用的是 `filter(Boolean)` 后的计数：一页内若有全 NULL 行（CONCAT_WS 全 NULL → 空串被过滤）或 GROUP_CONCAT 截断残行，计数 < lim → 误判"末页"→ **后续页数据静默丢失**。应改用原始 split 计数或 SQL COUNT 校验。
- [server/src/engine/Extractor.js:507-512 中] MySQL `GROUP_CONCAT` 默认 group_concat_max_len=1024：宽表/长值页在 DB 侧先截断，截断点可能落在行中间 → 解析错位产生脏数据 + 提前触发上述末页误判。sqlmap 的等价做法是逐行提取或调大变量；当前实现未处理也未声明该边界。
- [server/src/engine/Extractor.js:523 低] maxRows 检查在 push 之后：越界溢出最多一页（lim 行），可接受但不精确。
- ✓ 内存面结论：UNION 分页路径 rows 对象数上限 = maxRows(+1 页)，单页 val 字符串受 lim 行约束；`all` 无引用泄漏。默认配置（lim=100 → 5000 行上限）内存可控。

### 2.3 其它提取链路

- [server/src/engine/Extractor.js:443 低] extractScalar 回显列兜底硬编 `idx=1`（第 2 列）：discoverEchoColumns 失败且回显列非第 2 列时整次提取静默 null。已有 echoCols 复用机制兜底大部分场景，残余风险低。
- [server/src/engine/Extractor.js:874-880 低] predictOutput 缓存键含 scanId+target 对象身份（WeakMap）：createTarget 每次 nanoid 新对象 → 缓存实际只在同扫描多注入点间复用，跨扫描复用注释描述的能力从未生效（无害，注释过期望修正）。
- [server/src/engine/Extractor.js:865 低] 放弃的字节置 0，TextDecoder 将 0x00 原样解码为 NUL 字符留在结果串中（不可见但污染比对/落盘）；建议放弃字节改用占位 '?' 或截断。
- [server/src/engine/ColumnTypeEnumerator.js:36 中] SQL Server 类型查询未过滤 `TABLE_SCHEMA`（Extractor.SCHEMA_QUERY 同位置用 `'dbo'`）→ 多 schema 库中同名表的列类型会跨 schema 混入 byName 映射，类型标注张冠李戴。两处判据应统一。
- [server/src/engine/extractScope.js:286-300 中] search 模式虽限 MAX_DBS=3 / MAX_TABLES_PER_DB=10，但对每库**全部** tbls 逐一 enumerateColumns（每表 ≥1 请求），匹配过滤在客户端做——大 schema 下 3×50 表 = 150+ 请求起步。可在 SQL 侧 LIKE 过滤（`WHERE column_name LIKE '%kw%'`）把请求量降为 O(dbs)。

## 三、Exploiter.js：os-shell / file-write SQL 拼接构造核查

### 3.1 命令执行路径（多方言）

- [server/src/engine/Exploiter.js:310-318 中] **pgOsShell：命令串单引号未转义**。`COPY cmd_out FROM PROGRAM '${cmd}'` 直接内插：cmd 含单引号即破坏语句（扫描器侧语法损坏，非注入风险——输入来自本工具用户）；应 `cmd.replace(/'/g,"''")`。同函数 `CREATE TABLE cmd_out` 未加 TEMP → 落在当前 schema 持久化，并发两个利用会话互相 DROP/CREATE 竞态。
- [server/src/engine/Exploiter.js:317 低] pgOsShell 回显 `SELECT out FROM cmd_out` 返回多行（命令输出逐行一行）而 extractScalar 只取首个回显列首行 → **只回显第一行输出**，长输出静默截断。应 `SELECT string_agg(out, CHR(10)) FROM cmd_out`。msOsShell L329 同病（`SELECT o FROM #c` 多行临时表）。
- [server/src/engine/Exploiter.js:322-330 中] **msOsShell**：xp_cmdshell 的 cmd 同样未做 cmdshell 层转义；且 `CREATE TABLE #c` 临时表 + 后续独立请求 `SELECT o FROM #c` —— **#temp 表作用域随连接结束销毁**，HTTP 注入模式下两条堆叠语句若经不同连接执行则第二查必空（同一连接池复用才偶发命中）。直连模式单连接可用；HTTP 模式该路径可靠性存疑，应在文档标注或改为表变量+同语句回显。
- [server/src/engine/Exploiter.js:339-348 中] **myOsShell**：`sys_eval('${cmd}')` cmd 单引号未转义（同 §3.1 首条）。路径 1/2 用 extractScalar 探测 UDF 是否注册：UDF 不存在时 DB 报错 → _send 捕获返回 null → 判定"未注册"逻辑成立 ✓。
- [server/src/engine/Exploiter.js:442-447 中] **疑似 bug：PostgreSQL UDF 注册类型非法**。`RETURNS ${ret}` 中 ret 取值 'STRING'/'INTEGER' 是 **MySQL UDF** 类型词汇；PG 的 CREATE FUNCTION 要求 `RETURNS text/int` → PG 分支 udfInstall 生成的 SQL 必然语法错误，PG UDF 投递功能整体不可用（MySQL 分支 STRING/INTEGER 合法）。
- [server/src/engine/Exploiter.js:396-424 低] oracleOsShell：Java 源多行堆叠投递对部分驱动/中间件不可达（换行被 WAF/驱动剥离），失败被 catch 吞掉后仍走 SELECT 回显并返回 ok:true（val 可能为 null），调用方需自行判 value。建议 val==null 时降级 ok:false。

### 3.2 文件读/写路径

- [server/src/engine/Exploiter.js:97-99 中] FILE_WRITE 三方言拼接核对：
  - MySQL `SELECT '${content''}' INTO OUTFILE '${path}'`：content 已 '' 转义 ✓，但 **path 未转义**（含引号路径破坏语句，低危）；
  - PostgreSQL `COPY (SELECT '...') TO '${p}'`：同上；COPY TO 写入内容带末尾换行、无列头 ✓ 与 readback includes 前 40 字节校验兼容；
  - SQL Server `EXEC master..xp_cmdshell 'echo ${c} > ${p}'`：**双重上下文只转义了 SQL 层**——content 经 '' 转义后进入 cmd.exe，`& | ^ < >` 等 shell 元字符与换行均未处理 → 含元字符内容写盘失真或命令注入到 *目标 OS shell*（内容可控场景=本工具用户自身，风险可接受但 verified 回读大概率 false）。建议改 Base64 编码 + certutil 解码两步写（sqlmap 同思路）。
- [server/src/engine/Exploiter.js:199-207 中] oracleFileRead 分段循环每段都重新执行 `sqliload(...)` 整文件读取再 SUBSTR → 服务端 O(n²) I/O（100KB 文件 = 25 段 × 全文件读 25 次）；且上限 400KB 硬编码。建议先落 CLOB 到临时表/会话或按段递增窗口。
- [server/src/engine/Exploiter.js:59-73 中] **buildStackPageSql：SQL Server 缺 ORDER BY**。T-SQL 的 `OFFSET..FETCH NEXT` 语法要求 ORDER BY 子句（SYS_QUERIES['SQL Server'].data L108 正确加了 `ORDER BY (SELECT NULL)`，此副本漏掉）→ deepDump 在 MSSQL 上分页提取必然语法失败，触发 fallback 链路误判"目标不支持堆叠"。两处判据漂移的实证，建议 deepDump 复用 SYS_QUERIES.data 或抽公共分页构造器。
- [server/src/engine/Exploiter.js:66 低] MySQL/SQLite 页聚合 `GROUP_CONCAT(... SEPARATOR CHAR(10))`：受 group_concat_max_len=1024 截断问题与 §2.2 相同，deepDumpPageSize 默认 200 行远超 1024 字节容量 → 实际每页常被截断，`rows.length < lim` 末页判断同样失真。
- ✓ 核对通过项：★FIX-1 Oracle 目录转义、★FIX-2 privProbe SUBSTRING_INDEX、★FIX-3 regRead 回显、★FIX-4 PG 跨库限定名四处修复与注释描述一致；stackedQuery boundary 前缀闭合语义正确；TAKEOVER_CAPS 风险矩阵与实际能力声明一致。

## 四、scanRunner / crawler / TargetParser / DBFingerprinter：并发生命周期与取消传播

### 4.1 取消传播（stop 后在途请求是否真正中断）

- [server/src/engine/ScanManager.js:147-155 + 全引擎 高] **结论：不中断，仅协作式检查点**。`stop()` 只置 `s.cancelled=true` 并 retire；全仓库 grep 确认 **HttpClient 无 AbortController/AbortSignal 支持**（唯一 abort 在 ReportAI 的 fetch 超时）。实际语义分层：
  - ✓ 点间：Scheduler worker 每点开始前 `if (s.cancelled) return`（scanRunner L161）；提取任务每项开始前兜底（L386）；
  - ✓ 阶段间：检测聚合后、二阶/NoSQL/提取前集中检查（L355-368），用户 stop 后不再发起**新的**检测与写请求（★FIX-1 修复了旧版 stop 后仍跑二阶写请求的问题，已核实）；
  - ✗ 点内：单个 point 的 detector 循环一旦开始不可中断——ErrorDetector ≤10+10 模板串行、TimeBlind 未知库 5 库遍历 ≈80s sleep 墙钟、OobDetector waitForToken 2×5s 盲等、盲注提取整值循环——这些在 stop 后**继续对目标发包直至自然结束**；
  - ✗ 在途 HTTP：已发出的请求等待响应/超时（默认 5s）才释放。
  
  综合最坏情形：大目标 stop 后仍有分钟级残留流量。建议：① HttpClient.request 增加 signal 参数（axios 原生支持）；② Scheduler.run 接收 isCancelled 回调在每个 item 边界检查；③ OobDetector.waitForToken 改为可唤醒。

- [server/src/engine/scanRunner.js:51 中] `parser.discover`（含 crawl 深度爬取，最多 maxTotalPages=50 页 × 超时）发生在任何 cancelled 检查之前：discover 期间 stop 无效。crawl 完成后才进入可取消区。建议 discover 分页回调检查 cancelled 提前返回。

### 4.2 并发生命周期

- [server/src/engine/scanRunner.js:150-156 ✓] Scheduler 自适应并发（错误率>20% 减半、延迟>3s 减 25%、<800ms 回升）逻辑正确；retry=0 收敛到 HttpClient 单层重试，消除 (retry+1)² 重试风暴的注释与实现一致。
- [server/src/engine/scanRunner.js:76-88 ✓] 会话恢复竞态处理到位：setPoints await 落盘、finalize 先于 completed 状态、resume 合并历史 vulns 且按 pointId+technique 去重。
- [server/src/engine/crawler.js:124-151 低] BFS 串行取页（逐 await），50 页上限下墙钟 = 50×RTT；无并发但也无取消钩子。同域判定用 host（含端口）✓；URL 规范化只去 hash，query 不同的分页链接会各自入队（受上限约束，可接受）。
- [server/src/engine/TargetParser.js:244-296 ✓] 爬取结果与既有点去重 key 设计合理；表单点 CSRF/storeKind 标注完整。level≥5 才启用爬取的门控清晰。
- [server/src/engine/DBFingerprinter.js:168-183 高→中] **疑似 bug：时间向量定库不减基线 RTT → 高延迟网络错误定库**。`Date.now()-t0 >= thresholdMs(800)` 判定命中：跨境/高 RTT 目标（单请求 >800ms）时 TIME_VECTORS 第一个向量即"命中"并返回其 dbms → 方言判错 → 后续所有 detector 用错误方言 payload（时间模板/报错模板/WRAP）→ 全面漏报。基线响应就在手边（fingerprint L74-75 已抓 baseline）却未测量其耗时参与扣除。修复：threshold 与 (baselineRtt + sleepSec×1000) 取 max，或直接复用 robust 的 μ+z·σ 语义。
- [server/src/engine/DBFingerprinter.js:110-135 低] UNION 版本探测按 DB_VERSION 全库顺序轮询（~15 库 × 1 请求），未利用第 2 步 header 特征命中结果提前收敛；请求预算可控但可优化。

## 五、sessionStore.js：会话恢复原子写与损坏容错

- [server/src/core/sessionStore.js:120-131 中] **非原子写**：`fs.writeFile` 直接覆写目标文件。进程在写入中途崩溃/断电 → JSON 半截 → 下次 `load()` parse 失败被 catch 吞掉返回 null → **resume 静默退化为全新扫描**（历史命中丢失，无任何告警）。标准修复：写 `filePath + '.tmp'` 后 `fs.rename` 原子替换（同目录保证同分区）；load 失败时 logger.warn 提示会话文件损坏。
- [server/src/core/sessionStore.js:40-47 中] **withFileLock 清理逻辑恒不生效（疑似 bug）**：`next.then(() => { if (fileLocks.get(filePath) === next.catch(() => {})) ... })` —— `next.catch()` 每次调用创建**新** Promise 对象，与 L43 存入的引用永不相等 → `fileLocks.delete` 死代码，Map 条目永不清理。每路径一条量级小、实害有限，但注释声称"防无界增长"与实际不符；且该比较分支本身是对已 settled promise 的多余挂载。
- [server/src/core/sessionStore.js:31-35 低] sanitizeConfigForDisk 只剥 auth/proxy；文件头注释声称同时剥离 cookieParams/headerParams——实际这两者挂在 target 上、本就不在 snapshot 里，注释误导。若未来把 headerParams 收进 config 会直接漏脱敏，建议按注释补齐剥离列表。
- [server/src/core/sessionStore.js:133-149 低] load 无 schema 校验：perPoint 条目缺 status 字段会被 pendingPointIds 计为待跑（安全方向，多扫一遍）；但 vulns 数组元素结构未验证，手工编辑/旧版本文件可能造成 report 合并阶段读 undefined.technique（scanRunner L440-441 `v.pointId === ...` 容忍 undefined 不崩）。可接受。
- ✓ 核对通过：P2-10 同路径写盘串行化语义正确（前序失败不阻断后续）；savePointResult 的 vulns 按 pointId+technique 幂等去重正确；路径白名单拒绝目录穿越与隐藏文件有效。

## 六、死代码与未用导出扫描

- [server/src/core/statsHelper.js:24-30 低] `ratioTrue`：@deprecated，全仓库仅 statsHelper.test.js 引用。删除函数 + 测试，或保留并在导出处标注 test-only。
- [server/src/engine/columnGuess.js:36-39 低] `createColumnGuessCache`：src/tests 均无调用（实际缓存是 Extractor._colGuessCache 模块级 Map）。死导出。
- [server/src/engine/Detector.js:63 低] `point._baselineTitle = this._extractTitle(baseBody)`：赋值后无任何读取（matchTitle 走真/假响应自带 title）。死赋值，或按原意接线到 _matchByTitle 作基线对照。
- [server/src/engine/detectors/InlineQueryDetector.js:89 低] `INLINE_MARKER` 具名导出仅测试文件引用；文件内自用。可收窄为模块内常量 + 测试走行为断言。
- ✓ **存活确认**：engines/sqlmapBridge.js 被 api/sqlmapRoutes.js 正常引用（buildArgs/start/stop/getReport 全链路使用，且测试覆盖），**不是死代码**；statsHelper 其余导出（similarityRate/twoProportionZ/isSignificant/baselineNoiseRate/adaptiveMinStable/chunkSimilarity/dynamicBlockFilter/effectiveThreshold/adaptiveTimeFloor）均有生产调用；Extractor 的 WRAP re-export 有测试依赖；Exploiter RISK_LEVELS/TAKEOVER_CAPS 内部 + 路由层使用。
- [server/src/engine/Extractor.js ↔ DBFingerprinter.js ↔ UnionDetector.js 低→中] **循环导入三角**：Extractor imports {WRAP, fromDummy} from DBFingerprinter；DBFingerprinter imports {_colGuessCache} from Extractor；UnionDetector imports {_colGuessCache} from Extractor。当前全部是函数体/方法内的延迟使用，ESM 下能跑，但任何一方改为模块顶层求值使用即踩 TDZ；也是"猜列缓存"这一共享状态散落三处的根因。建议把 _colGuessCache 下沉到 columnGuess.js（与 binaryGuessColumns 同居）。

## 七、疑似 bug 单独列节（按危害排序）

1. **[StackedDetector.js:79-86 高] 慢目标误报 Critical**：堆叠判定 `elapsed >= 固定 thresholdMs` 无基线补偿，与注释声称的 TimeBlind 同构不符。正常响应 ≥ 阈值的慢站上，任意点都会被确认为堆叠注入并强制 Critical 定级（scanRunner L331 对 stacked 特权定级并压制其它技术证据）。**误报方向、后果最重**。
2. **[InlineQueryDetector.js:44-49 高] 反射目标必然误报**：命中条件「test 含标记 && base 不含」对任何回显参数值的页面恒真（标记字面量随注入串被反射）。UnionDetector 已有 `_gateInjection` 防同类问题，此处缺失。
3. **[Extractor.js:421 + UnionDetector.js:108 高→中] _colGuessCache 跨目标串数据**：缓存 key 只用 `point.id` = sha256(location:param:actionUrl) 前 8 位（models.js L60-64），**不含 host**。两个目标存在同路径同名参数（`/item.php?id=` 极常见）时，后扫目标直接复用前目标的列数 → UNION 标记列数错位 → 提取失败或错列数据。模块级 Map 且仅 freshQueries 清空，进程生命周期内跨扫描持续污染。修复：key 掺入 target.baseUrl hash。
4. **[DBFingerprinter.js:168-183 中] 时间定库不减 RTT**：800ms 固定阈值 vs 高延迟网络 → 第一个时间向量即误命中 → 方言判错 → 全链路 payload 用错方言（漏报级联）。baseline 在手未测耗时。
5. **[Exploiter.js:442-447 中] PG UDF 注册 SQL 类型非法**：RETURNS STRING/INTEGER 是 MySQL 词汇，PG 分支生成的 CREATE FUNCTION 必然语法错误 → PG UDF 投递功能不可用。
6. **[Exploiter.js:59-73 中] buildStackPageSql 的 MSSQL 分页缺 ORDER BY**：OFFSET/FETCH 语法错误 → deepDump 在 SQL Server 上恒失败。与 SYS_QUERIES.data 正确副本形成判据漂移实证。
7. **[sessionStore.js:40-47 中] withFileLock 清理比较恒 false**：`next.catch(()=>{})` 每次新建对象，锁条目永不删除；注释承诺的防无界增长未兑现。
8. **[Extractor.js:521-523 中] dumpData 末页误判丢数据**：`filter(Boolean)` 后计数 < lim 即终止分页，全 NULL 行/截断残行触发提前终止。
9. **[Detector.js:57-77 中] 锚点模式下 probeBoundary 恒返回空串**：matchAnchors 对所有闭合候选返回同一结果，首个空前缀必命中 → 字符串上下文 boundary 探测在 --string 配置下失效。

## 八、严重级别汇总

### 高（4 项）
| # | 位置 | 问题 |
|---|---|---|
| H1 | StackedDetector.js:79-86 | 无基线补偿 → 慢目标误报 Critical |
| H2 | InlineQueryDetector.js:44-49 | 无反射门控 → 回显页面必然误报 |
| H3 | ScanManager.js:147 + httpClient | 取消传播缺失：stop 后点内循环与在途请求不中断（分钟级残留流量） |
| H4 | Extractor.js:421 / UnionDetector.js:108 | _colGuessCache 按 point.id 跨目标共享 → 列数缓存串数据 |

### 中（14 项）
columnGuess 二分单调性假设失效（200 错误页）· UnionDetector 门控拒真漏报边界 · UnionDetector Oracle/DB2 缺伪表 FROM · BooleanBlind 大 body 头尾采样漏报边界 · TimeBlind 未知库 5 库遍历墙钟 ~80s · DBFingerprinter 时间定库不减 RTT · pgOsShell/msOsShell/myOsShell 命令单引号未转义 · msOsShell #temp 跨请求作用域存疑 · PG UDF 类型非法 · buildStackPageSql MSSQL 缺 ORDER BY · FILE_WRITE cmdshell 层元字符未处理 · dumpMaxRows 默认值随 lim 联动非绝对兜底 · dumpData 末页误判 + GROUP_CONCAT 1024 截断未处理 · sessionStore 非原子写 · probeBoundary 锚点模式失效 · ColumnTypeEnumerator MSSQL schema 过滤不一致 · extractScope search 全表枚举列请求量（部分与前述重复计一次）

### 低（12 项）
twoProportionZ nB 口径 · ErrorDetector 基线剔除全等比较 + MariaDB/MySQL 模板重复投放 · StackedDetector 混合模板采样 · fileWrite path 未转义 / regRead 参数未转义 · oracleFileRead O(n²) 重读 · oracleOsShell ok:true 但 value null · extractScalar 兜底硬编第 2 列 · predictOutput 跨扫描复用从未生效 · 放弃字节解码为 NUL 污染值 · sessionStore 注释与脱敏实现漂移 + load 无 schema 校验 · 死代码四项（ratioTrue/createColumnGuessCache/_baselineTitle/INLINE_MARKER 导出）· 循环导入三角 Extractor↔DBFingerprinter↔UnionDetector · crawler 串行无取消钩子 · NoSQL/GraphQL 探测入口形态单一

### 总体结论

引擎主干质量较高：布尔三条件判定、blindRobust μ+z·σ 统计链路、sendConcurrent 计时语义、★FIX 系列修复均经核实与注释一致；请求预算（探测 ≤8 条报错模板、二分猜列 ~6 请求、盲注提取 N≈8+L×(6~11)）有界且文档诚实。主要风险集中在四处：① **两个检测器的误报路径缺基线/门控防护**（H1/H2，直接影响报告可信度）；② **取消传播只有协作式检查点**（H3，授权测试的流量控制承诺打折）；③ **跨目标共享的可变模块状态**（H4，多目标工作流正确性）；④ **多方言 SQL 构造的第二份拷贝漂移**（MSSQL ORDER BY、PG UDF 类型——同一逻辑两处实现的经典事故，建议统一收敛到单一方言构造器）。建议优先修复 H1-H4 与 §七 1-4 项，其余可随迭代收敛。







