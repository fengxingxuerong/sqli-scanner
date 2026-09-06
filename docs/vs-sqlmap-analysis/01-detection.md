# 检测能力 / 准确率 差距分析（vs sqlmap）

> 方向：检测能力与准确率。对照基准：sqlmap（检测技术 BEUSTQ、40+ DBMS、data/xml/payloads 测试用例体系、tamper 脚本库、主动指纹、动态内容感知的页面比较）。
> 本报告为只读分析，未改动任何代码。所有引用均为 `file:line` 级证据。

---

## 1. 现状梳理：本项目检测能力全景

### 1.1 编排架构

- `ScanManager`（`server/src/engine/ScanManager.js`）为门面：发现注入点 → DB 指纹 → WAF 指纹 → 检测器调度 → 聚合去重 → 提取 → 报告。
- 检测器注册表：`ScanManager.js:36-52`，共 8 类探测器：
  - 一阶主调度：`UnionDetector / ErrorDetector / BooleanBlindDetector / TimeBlindDetector / StackedDetector / OobDetector / InlineQueryDetector`（`inline` 为 opt-in，`ScanManager.js:51-52` push 进主数组）。
  - 补充趟（不进一阶循环）：`SecondOrderDetector`（`ScanManager.js:46`，`_runSecondOrder` at 386-430）、`NoSqlInjectionDetector`（`ScanManager.js:48`，`_runNoSql` at 435-464，覆盖 NoSQL/GraphQL/SSTI）。
- 调度分两层：FAST（union/error/boolean/inline）并行抢断、SLOW（time/stacked/oob）并行采样（`ScanManager.js:227-258`）；`stacked` 被选中时即使 FAST 命中仍跑 SLOW。
- 指纹：`DBFingerprinter`（`engine/DBFingerprinter.js`）、`WafIdentifier`（`core/waf/WafIdentifier.js`，复用指纹基线，零额外发包）。
- 提取：`Extractor`（`engine/Extractor.js`）+ `Exploiter`（`engine/Exploiter.js`，sql-shell / file-read / file-write / os-shell / UDF / 注册表 / 权限探测 / 堆叠深度提取兜底）。

### 1.2 注入点类型（TargetParser，`engine/TargetParser.js:23-70`）

- 支持：URL 查询参数（GET/POST 通用）、Body 表单/JSON 参数、Cookie 参数、Header 参数。
- 可选表单爬取（`crawlForms`，`TargetParser.js:63-67, 138-161`）：解析 `<form>` 生成 body 注入点，识别 CSRF token、POST 表单标记为二阶存储点（`isStorePoint`）。
- 直连模式（`-d` 对标）：SQL 模板 `{INJECT}` 替换（`TargetParser.js:27-34`，`injection.js:9-13`）。

### 1.3 四类核心探测器实现与判定逻辑

| 探测器 | 文件 | 判定逻辑 | 误报控制手段 |
|---|---|---|---|
| Union | `detectors/UnionDetector.js` | ORDER BY 二分猜列（`columnGuess.js:6-22`，上限 50）→ 标记 `SQLISCANNER<i>` UNION 回显定位回显列（`UnionDetector.js:46-62`） | 回显标记做大小写不敏感匹配（`UnionDetector.js:61`） |
| Error | `detectors/ErrorDetector.js` | 注入报错 payload，匹配跨库 `ERROR_SIG` 正则（`payloads.js:430-431`） | 基线比对（页面固有报错剔除，`ErrorDetector.js:42-43`）+ 二次发送确认（44-47） |
| Boolean | `detectors/BooleanBlindDetector.js` | 真/假条件对（`AND '1'='1` / `'1'='2'`）比对响应差异，要求 真≈基线 且 假≠基线 且 真假有意义差异（legacy，31-82） | 基线 2 次采样（legacy）/ 鲁棒分支：基线指纹集 + 真假对重复采样一致率 + 基线噪声地板 + 两比例 z 检验显著性 + 自适应一致率门槛（`_robustDetect` 87-206，`core/statsHelper.js:51-100`） |
| Time | `detectors/TimeBlindDetector.js` | 注入 `SLEEP/pg_sleep/WAITFOR`，耗时 ≥ 阈值且稳定 ≥ 半数次（legacy，32-85） | 基线测速 + 鲁棒分支：基线 μ+σ 分布感知阈值（μ+z·σ，自适应绝对下限）+ 稳定率（`_robustDetect` 89-153） |
| Stacked | `detectors/StackedDetector.js` | `;` 追加独立延迟语句，连续 ≥ 半数次延迟即确认（42-102） | 与 Time 同构；Oracle 跳过（31-33） |
| OOB | `detectors/OobDetector.js` | 注入 `LOAD_FILE/COPY PROGRAM/xp_dirtree/UTL_HTTP` 触发目标回连 HTTP 接收端（21-77） | token 轮询确认；OOB 不套 tamper（45） |
| Inline | `detectors/InlineQueryDetector.js` | 注入 `SELECT '__S__INL__E__'` 子查询，标记随响应回显即确认（26-52） | 基线排除标记本就存在 |
| Second-order | `detectors/SecondOrderDetector.js` | 三态判定：基线无报错 && 存储探针后有报错 && 阴性对照无报错（41-65） | 三态 + 可选 CSRF 刷新（136-158） |

### 1.4 payload 库规模（`engine/payloads.js`）

- 14 种 DBMS：MySQL / PostgreSQL / SQL Server / SQLite / Oracle / MariaDB / TiDB / DM8 / ClickHouse / DB2 / Sybase / Firebird / Informix / H2（`payloads.js:401`）。
- 模板总数 **190 条**：union 42、error 42、boolean 56、time 30、stacked 20；每库每技术仅 2-4 条（脚本统计输出见下）。
- OOB 模板 12 条（`payloads.js:312-346`），仅 MySQL/MariaDB/PG/MSSQL/Oracle/TiDB/DM8，SQLite/ClickHouse 留空。
- 二阶探测探针 5 条（`SECOND_ORDER_PROBES`，`payloads.js:435-441`）。
- 存在 `second_order`/`oob`/`stacked`/`inline` 技术位（`TECHNIQUE_TYPES`，`payloads.js:7`），默认 techniques 仅 union/error/boolean/time（`config/defaults.js:43`）。

### 1.5 DB 指纹维度（`engine/DBFingerprinter.js`）

两条识别路（53-119）：
1. 响应头特征（`FINGERPRINT`，`payloads.js:349-369`：X-Powered-By / Set-Cookie / Server 正则）→ 命中即定库。
2. UNION 版本回显：ORDER BY 猜列 → 标记定位回显列 → 各库版本函数（`DB_VERSION`，`payloads.js:373-399`）逐库探测，匹配 sig 即定库（MariaDB 优先于 MySQL，负向排除）。

### 1.6 tamper 插件清单（`core/tamper/`）

- **62 个插件**（`plugins/` 目录 62 个文件），由 `applyTampers.js:4-68` 导入并注册到 `TamperRegistry`（单例）。
- 链式执行（`applyTampers.js:146-153`），统一入口 `obfuscateWithConfig`（166-181）：tamper 开 → 链式；否则 legacy `obfuscate`；否则原样。
- 分类：空格替换（space2comment/dash/hash/plus/randomblank/nbsp/morecomment/mssqlblank/mssqlhash/mysqlblank/mysqldash/blank）、编码（charencode/chardoubleencode/charunicodeencode/base64encode/htmlencode/overlongutf8/unicode）、大小写（randomcase/uppercase/lowercase）、运算符替换（between/greatest/least/equaltolike/symboliclogical）、关键字变形（keywordSplit/comments/versioned*/modsecurity*）、函数改写（ifnull2*）、库专属（sleep2delay/sleep2pg/sp_password/misunion/unionalltounion）等。
- WAF 指纹库覆盖 30 个厂商（`core/waf/wafRules.js`），`wafRecommend`（`core/waf/wafRecommend.js`）给出 tamper 建议但**不自动套用**（`ScanManager.js:368-374`）。

### 1.7 数据提取（`engine/Extractor.js`）

- UNION 标量提取：`extractScalar`（217-236），复用检测阶段回显列 `point.echoCols`，`__S__...__E__` 包裹 + 控制字符 0x1E/0x1F 分列分行（`SYS_QUERIES`，25-79）。
- 枚举链：库→表→列→数据（`enumerateDatabases` 239 / `enumerateTables` 249 / `enumerateColumns` 259 / `dumpData` 269），MySQL/PG/SQLite/MSSQL 支持 `LIMIT/OFFSET` 分页续拉（276-301），Oracle 受 ROWNUM 单页限制。
- 并发：表级并发 `dumpConcurrency`（默认 4）、库级并发 `dumpDatabaseConcurrency`（默认 2）（306-350）。
- 盲注二分提取：`extractBoolean`（373-417）——长度二分（0-255 字节上界）+ 多字符并行二分（`extractConcurrency`=4，每批共用 false 基准）+ UTF-8 逐字节还原（TextDecoder）。
- 内联提取：`extractInline`（471-485），复用 `__S__/__E__` 包裹。
- 堆叠深度提取兜底：`Exploiter.deepDump`（`Exploiter.js:207-256`，Oracle 走 XMLAGG→CLOB→DBMS_LOB.SUBSTR 分段，规避 LISTAGG 4000 截断）。

### 1.8 准确率保障机制

- 盲注统计判定（默认开，`config/defaults.js:67-81`）：基线噪声率 → 自适应一致率门槛 → z 检验显著性 → 基线 μ/σ → 分布感知时间阈值。
- 判定轨迹透传（`result.trace`，`BooleanBlindDetector.js:181-204` / `TimeBlindDetector.js:139-151`），前端可展开审计。
- Error：基线剔除 + 稳定二次确认。
- 二阶：三态 + 阴性对照。
- 会话持久化/resume（`core/sessionStore.js`，`ScanManager.js:158-170`）。
- 限速：令牌桶 3 req/s（`httpClient.js:151`）+ 并发池（`services/Scheduler.js`）。

---

## 2. 与 sqlmap 差距清单

> 对照基准：sqlmap 检测技术 BEUSTQ（Boolean/Error/Union/Stacked/Time/Inline-OOB），40+ DBMS，payload 库按 `data/xml/payloads` 分技术/分库/分子句组织，主动指纹（含报错/时间多向量），动态内容感知的页面比较，WAF 探测后自动套 tamper，`--level 1-5 / --risk 1-3`，tamper 官方目录约 60-80 个脚本。

### 差距 D1【高影响】布尔/时间/报错 payload 仅适配"字符串上下文"，数字型注入点大面积漏检

- **sqlmap 做法**：注入前自动探测参数上下文（数值型/字符型/搜索型/JSON 等），数值上下文用 `AND 1=1 / AND 1=2` 等无引号 payload，字符上下文用 `'` 包裹，并靠 boundary 系统适配引号/括号。
- **本项目现状**：
  - Boolean 模板恒为带引号形式：`"{ORIG}' AND '1'='1"` / `'1'='2'`（`payloads.js:22-25`，四库同构）。原值 `id=1` 注入后为 `1' AND '1'='1`，在数值上下文直接语法报错，真/假响应无差异 → 布尔检测漏报。
  - Time 模板同样恒带引号：`"{ORIG}' AND SLEEP({SLEEP})-- -"`（`payloads.js:28-30`），且仅取 `templates[0]`（`TimeBlindDetector.js:39,94`），数值上下文 `1' AND SLEEP(2)` 语法错误 → 时间检测漏报。
  - Error 模板同样以引号开头（`payloads.js:16-20` 等），数值上下文漏报。
- **影响**：最经典的 `id=1` 类数字参数注入点在布尔/时间/报错三条技术线下全部漏检（仅 UNION 因含 `{ORIG} UNION` 无引号变体可命中，`payloads.js:12`）。这是召回率最大缺口。

### 差距 D2【高影响】无 boundary（前缀/后缀）探测，括号包裹 / 特殊闭合场景漏检

- **sqlmap 做法**：每个测试用例绑定 boundaries（prefix/suffix，如 `')`、`"))`、`'`、`--` 变体、`%` 通配），自动尝试闭合语法，并对 `--level` 递增扩展边界深度。
- **本项目现状**：所有 payload 固定以 `{ORIG}` 前缀 + `-- -` 后缀拼接（`Detector.js:38`，`payloads.js` 各模板），无闭合上下文探测。对 `WHERE x = (SELECT ... FROM t WHERE id='1')` 这类括号包裹注入点，`' AND '1'='1'` 拼接后括号不闭合 → 语法错误 → 漏检；对注释符被过滤（`--` 失效、需 `#`/`/**/`）的目标同样漏检。
- **影响**：真实应用大量存在的括号/拼接上下文注入点漏检。

### 差距 D3【高影响】UNION 回显列未做类型 CAST，严格类型 DBMS 报错漏检

- **sqlmap 做法**：回显列默认对表达式做 `CAST(... AS 类型)` 兼容（`--no-cast` 才关闭），并适配各库 NULL 列类型。
- **本项目现状**：`discoverEchoColumns`（`injection.js:74-90`）与 `UnionDetector.js:46-49` 注入的标记是裸字符串 `'SQLISCANNER<i>'`，无 CAST。当回显列类型为 INT 且 DBMS 严格（MSSQL `Conversion failed` / Oracle / PostgreSQL）时 `UNION SELECT 'x'` 报类型转换错误 → UNION 漏检；`DBFingerprinter` 的版本回显（`DBFingerprinter.js:103-117`）同样受影响。
- **影响**：MSSQL/Oracle/PG 上大量 UNION 注入点漏报，且指纹识别降级。

### 差距 D4【高影响】DB 指纹维度单一，无回显/无响应头特征时 DBMS 未知 → 方言错误

- **sqlmap 做法**：指纹是多向量主动探测——基于报错消息、基于时间（各库 sleep 函数差异）、基于注释语法、基于版本函数，且不依赖回显列。
- **本项目现状**：`DBFingerprinter` 仅两条路：响应头正则（`DBFingerprinter.js:79-87`）+ UNION 版本回显（89-117）。两者都不命中时返回 `dbms=null`，随后各检测器回退到 MySQL 模板（`BooleanBlindDetector.js:20`、`TimeBlindDetector.js:21`、`UnionDetector.js` 同）。
- **影响**：Oracle/PG/MSSQL 目标若无回显列、响应头又无特征，则 time 技术会用 MySQL 的 `SLEEP()`（Oracle 无此函数）→ 时间盲注漏检；boolean 模板虽兼容字符串比较但同样受 D1 限制；stacked 此时反而会遍历 4 库（`StackedDetector.js:35`）能覆盖一部分。

### 差距 D5【高影响】时间盲注点无法拖库（提取只走布尔通道）

- **sqlmap 做法**：Time-based blind 是独立提取通道，可经时间延迟逐位取数。
- **本项目现状**：`Extractor.extractBoolean` 是唯一的盲注提取通道（`Extractor.js:373-417`，布尔条件 `AND (...)` 判定响应差异）。`ScanManager.js:308-317` 对 time 漏洞调用 `extractor.extractProof(ctx)`，而 `extractProof`（`Extractor.js:462-466`）内部仍走 `extractBoolean`。
- **影响**：纯时间盲注点（布尔无差异）的版本证明与拖库全部失效——检测能命中、数据取不出来。这是"检测能力→利用能力"链条上的硬断点。

### 差距 D6【高影响】tamper 与提取/指纹链路的标记大小写破坏

- **sqlmap 做法**：tamper 作用于 payload 后，提取/指纹标记匹配使用随机化不敏感的锚点设计；且 sqlmap 标记（`__S__` 等）经过 `--no-cast`/解码器保持稳定。
- **本项目现状**：
  - 检测层已打补丁：`SQLISCANNER<i>` 回显用 `toLowerCase().includes(...)` 大小写不敏感（`injection.js:85-88`、`UnionDetector.js:61`）。
  - **提取/指纹层未打补丁**：`extractScalar` 用大小写敏感正则 `body.match(/__S__(.*?)__E__/s)`（`Extractor.js:234`）；`DBFingerprinter` 同样（`DBFingerprinter.js:114`）；`InlineQueryDetector.js:45` 用大小写敏感 `includes(INLINE_MARKER)`。
  - `randomcase`（`tamper/plugins/randomcase.js:12-16`）对所有字母随机大小写，会破坏 `__S__/__E__` 与内联标记；`charunicodeencode` 等编码插件同样。
- **影响**：一旦开启 `randomcase`/`charunicodeencode` 等 tamper，**拖库、指纹、内联提取全部静默失效**（提取返回 null），而检测层却正常——形成"检测命中但提取全空"的隐性故障。

### 差距 D7【中影响】payload 库规模与 sqlmap 差 1-2 个数量级

- **sqlmap 做法**：`data/xml/payloads/` 按技术 × DBMS × 子句（WHERE/ORDER BY/GROUP BY/HAVING/LIMIT/UPDATE 等）组织数千条测试用例，每条带边界、依赖（如 `requires: MySQL >= 5.1`）、编码提示、注释变体。
- **本项目现状**：每库每技术 2-4 条、共 190 条（见 1.4），且**无子句位置感知**——payload 只面向 `WHERE value=` 注入点；ORDER BY 位置（`ORDER BY (SELECT...)`）、LIMIT、HAVING 等注入点全部未覆盖；`ORDER BY` 仅用于猜列（`columnGuess.js`）。
- **影响**：覆盖度低；对 ORDER BY/LIMIT 注入点、对需要多步闭合的复杂注入点漏检。

### 差距 D8【中影响】响应相似判定朴素（最长公共前缀），无动态内容块识别

- **sqlmap 做法**：内置"页面比较"引擎，识别每次刷新都变化的响应片段（计数器、广告、时间戳、anti-CSRF）并自动排除；并提供 `--string/--not-string/--regexp/--code/--text-only/--titles` 精确锚点。
- **本项目现状**：`BooleanBlindDetector._similar` 用"长度容差 + 最长公共前缀 ≥85%"（`BooleanBlindDetector.js:241-250`）。若动态内容位于页面**首部**（导航栏时间戳等），LCP 立刻崩塌 → 真条件被误判偏离基线 → 漏报；反之若真假页都在首部被截断，差异被掩盖。
- **影响**：对首部动态页面误判率上升。统计分支（基线噪声 + 自适应门槛 + z 检验）能部分兜底，但锚点机制缺失。

### 差距 D9【中影响】无 WAF 主动探测与自适应 tamper

- **sqlmap 做法**：`--check-waf` 先发探测载荷，识别到 WAF 后自动应用对应 tamper 组合并持续降级重试。
- **本项目现状**：`WafIdentifier` 仅基于基线响应**被动**识别（`WafIdentifier.js:54-75`，零额外发包），`wafRecommend` 只给建议不自动套用（`ScanManager.js:368-374`），tamper 默认全关（`defaults.js:31`）。
- **影响**：默认配置下 WAF 拦截即漏检；需要用户手工在 UI 勾选 tamper，自动化程度低。

### 差距 D10【中影响】OOB 仅 HTTP 接收，无 DNS/SMB；触发原语覆盖少

- **sqlmap 做法**：OOB 默认 DNS（可带外回连数据），支持 HTTP/SMB；且 DNS 通道可完成无 HTTP 回显环境下的数据外带。
- **本项目现状**：`oobReceiver` 只监听 HTTP `GET /oob/:token`（`oobReceiver.js:55-67`），`OOB_PAYLOADS` 仅 12 条、每库 2 条（`payloads.js:312-346`）；callbackBase 需公网可达，内网测试需自建。
- **影响**：无 HTTP 出站、仅 DNS 出站的目标 OOB 检测无效；触发原语少导致命中率低。

### 差距 D11【中影响】注入点类型覆盖缺 URI 路径段 / 任意位置 `*` 标记

- **sqlmap 做法**：支持 URI 路径注入点（`-u /param1/*/param2`）、请求文件 `-r`、以及 GET/POST/Cookie/Header/UA/Referer 内任意 `*` 位置。
- **本项目现状**：`TargetParser` 仅覆盖 URL 查询参数 + body/cookie/header（`TargetParser.js:37-69`），无路径段注入点，无任意位置标记。
- **影响**：REST 风格 `/api/v1/users/{id}` 路径注入、`Referer/User-Agent` 注入等场景漏检（Header 注入需显式配置 `headerParams`，无 `*` 定位）。

### 差距 D12【中影响】无 level/risk 分级

- **sqlmap 做法**：`--level 1-5` 控制边界与 payload 深度，`--risk 1-3` 控制是否追加 OR-based、时间、OOB 等危险/高噪测试。
- **本项目现状**：固定一套检测流程，无分级；无 OR-based 布尔 payload（`payloads.js:22-25` 仅 AND 形式）。
- **影响**：无法对高价值目标做深扫；对 OR 拼接型查询（`WHERE user='x' OR 1=1`）注入点漏检。

### 差距 D13【低-中影响】误报控制缺口

- **sqlmap 做法**：UNION/错误回显均需与基线比对且带唯一性校验。
- **本项目现状**：
  - Union 检测**未比对基线**：`UnionDetector.js:46-62` 直接查回显标记，若目标页面天然含 `SQLISCANNER0` 之类字符串（概率低但存在，如缓存了历史扫描页）会误报；同理 `discoverEchoColumns`。
  - Error 判定只比较首个匹配串 `match[0] === baseMatch[0]`（`ErrorDetector.js:42-43`）：若页面本身含多条报错、注入后报错仍是首条同源（如同一错误信息在注入前后都出现），会漏判；`ERROR_SIG` 为单一跨库正则，覆盖不到的报错语形漏检。
  - 时间判定墙钟含令牌桶排队等待：`sendConcurrent` 的 `__elapsed` 从 `send` 前计时（`Detector.js:110`），而 `httpClient.request` 先 `bucket.acquire()`（`httpClient.js:151`）。限速 3 req/s 下并发采样排队，`__elapsed` 被抬升，稳定率可能虚高 → 时间误报风险。

### 差距 D14【低-中影响】盲注提取无稳定性校验/投票，抖动页面数据失真

- **sqlmap 做法**：提取通道有校验与按置信重试；可配置 `--charset` 优化。
- **本项目现状**：`extractBoolean` 每字节二分收敛即写（`Extractor.js:392-414`），布尔判定为单次 `trueData !== falseData`（`Extractor.js:405`）；无逐字节重测、无投票。页面抖动时单次误判直接产出错误字节（中文/二进制场景更敏感）。
- **影响**：动态页面上的拖库数据准确性无保障。

### 差距 D15【低影响】tamper 覆盖与质量对照

- **sqlmap 做法**：官方 `tamper/` 目录约 60-80 个脚本，含按厂商/场景组织（xforwardedfor、varnish、charunicodeescape、hexentities、decentities、if2case、plus2concat、plus2fnconcat、equaltorlike、0eunion、dunion、schemasplit、space2morehash 等），且 `space2comment` 用状态机避免破坏字符串字面量内空格。
- **本项目现状**：62 个插件，数量上接近，但：
  - 缺失上述约 15 个官方脚本（`xforwardedfor`、`varnish`、`charunicodeescape`、`hexentities`、`hex2char`、`decentities`、`if2case`、`plus2concat`、`plus2fnconcat`、`equaltorlike`、`0eunion`、`dunion`、`schemasplit`、`space2morehash` 等）；
  - 实现多为朴素正则/全局替换：`space2comment` 为 `/ /g`（`space2comment.js:12`）非状态机；`randomcase` 对全部字母含字符串字面量随机化（`randomcase.js:12-16`），除 D6 破坏提取标记外，也会随机化引号内内容改变语义；
  - 自研 `keywordSplit` 对 `SLEEP/CONCAT/VERSION` 等关键字中间插注释，与 MySQL 内联注释语法兼容性未标注。
- **影响**：部分 WAF 场景绕过失败；组合链偶发语义破坏。

### 差距 D16【低影响】DBMS 覆盖 14 种 vs sqlmap 40+

- 本项目 14 种（`payloads.js:401`）；sqlmap 额外支持 Access、MemSQL、CockroachDB、HSQLDB、MonetDB、Derby、Redshift、Vertica、Presto、Altibase、MimerSQL、CrateDB、Greenplum、Drizzle、Ignite、Cubrid、Caché、IRIS、eXtremeDB、FrontBase、Snowflake、Spanner、Aurora、OpenGauss 等。
- 本项目 DB2/Sybase/Firebird/Informix/H2 为"最小适配"，代码自标注"方言 payload 未经真实环境验证，待验证"（`payloads.js:196-305`、`SUPPORTED` 407-426）；提取层仅 5 库有完整数据字典（`Extractor.js:25-79`，Oracle 无 databases、SQLite 无 databases、ClickHouse 无 SYS_QUERIES）。
- **影响**：云数仓/嵌入式库场景缺失；边缘库检测为"半成品"。

---

## 3. 优化建议

> P0=高价值低成本，P1=高价值中成本，P2=锦上添花。

### 建议 1【P0】补数字型上下文布尔/时间/报错 payload 变体 + 上下文探测
- **内容**：在 `payloads.js` 每库每技术增加无引号变体（`{ORIG} AND 1=1` / `{ORIG} AND 1=2`、`{ORIG} AND SLEEP(n)`、数值型 error 如 `{ORIG} AND extractvalue(1,concat(...))`）；在 `BooleanBlindDetector`/`TimeBlindDetector`/`ErrorDetector` 的 detect 开头增加一次"数值上下文探测"（注入 ` AND 1=1` 与基线对比，有差异则走数值模板组）。
- **预期影响**：`id=1` 类最典型数字参数注入点三技术全量召回；直接修复 D1。
- **工作量**：S（模板 + 各检测器 10-20 行上下文分支）。
- **优先级**：P0。

### 建议 2【P0】UNION 回显列加 CAST 兼容
- **内容**：`discoverEchoColumns`（`injection.js:74-90`）与 `UnionDetector.js:46-49` 的标记列改用 `CAST('SQLISCANNER<i>' AS CHAR/NVARCHAR)`（按库写 WRAP 风格包装，如 `Extractor.js:7-18` 的 WRAP 体系复用）；`DBFingerprinter.js:103-117` 的版本回显同步。
- **预期影响**：MSSQL/Oracle/PG 严格类型库的 UNION 检测与指纹召回；修复 D3。
- **工作量**：S（新增 per-dbms cast 包装函数 + 3 处调用点替换）。
- **优先级**：P0。

### 建议 3【P0】提取/指纹/内联标记对 tamper 免疫
- **内容**：`Extractor.js:234`、`DBFingerprinter.js:114`、`InlineQueryDetector.js:45` 的标记匹配改为与检测层一致的大小写/编码不敏感匹配（如先 `toLowerCase` 或先还原；对 `charunicodeencode` 等编码插件可在 `obfuscateWithConfig` 增加标记白名单保护，`applyTampers.js:146-153` 前做 `__S__/__E__/SQLISCANNER` 占位暂存-还原）。
- **预期影响**：修复 D6——开启 tamper 后拖库/指纹/内联提取不再静默失效。
- **工作量**：S（标记正则 + 占位保护函数）。
- **优先级**：P0。

### 建议 4【P1】boundary 闭合探测
- **内容**：在 `Detector.buildRequest` 前新增一次闭合探测：对原值追加 `'`、`')`、`"))`、`"` 各发一次基线对比，识别闭合上下文；据此为布尔/时间/error payload 选前缀（`{ORIG}'` / `{ORIG}')` / `{ORIG}`）+ 后缀变体（`-- -` / `#` / `/**/` / 空），并将结果写入 `point.boundary` 供各检测器复用。
- **预期影响**：括号包裹、引号嵌套、注释符过滤目标召回；修复 D2、部分 D7。
- **工作量**：M（探测函数 + 各检测器消费 point.boundary）。
- **优先级**：P1。

### 建议 5【P1】时间盲注提取通道（最小实现）
- **内容**：`Extractor` 增加 `extractTime`：与 `extractBoolean` 同构（长度二分 + 多位置并行），但判定从"响应差异"改为"响应耗时 ≥ 阈值"，false 基准用非延迟请求；`ScanManager.js:308-317` 对 `time` 漏洞按技术路由到时间通道，`boolean` 仍走布尔通道。
- **预期影响**：修复 D5——纯时间盲注点可拖库/取版本。
- **工作量**：M（判定函数复用 + 时间采样稳定性逻辑）。
- **优先级**：P1。

### 建议 6【P1】增强 DB 指纹（报错特征 → DBMS 映射 + 时间向量）
- **内容**：`ERROR_SIG`（`payloads.js:430-431`）拆分为 per-dbms 报错签名表（ORA-/Microsoft SQL/PostgreSQL.*ERROR/SQLite3/DB2 SQL Error...），`DBFingerprinter` 在"无回显列"时用 error payload 的报错签名定库；再补充时间向量（注入各库 sleep 函数观测延迟定库）。`dbms=null` 时各检测器改为"遍历库模板"，而非死回退 MySQL（`BooleanBlindDetector.js:20`、`TimeBlindDetector.js:21`）。
- **预期影响**：修复 D4；无回显目标的 Oracle/PG/MSSQL 时间检测与方言正确。
- **工作量**：M。
- **优先级**：P1。

### 建议 7【P1】响应相似度升级 + 动态内容排除
- **内容**：将 `BooleanBlindDetector._similar`（241-250）的"长度容差 + LCP"升级为：① 分块比对（固定窗口 hash 或最长公共子序列近似），② 基线自比较时标记高频差异块并在判定中剔除（动态内容块排除），③ 可选锚点配置（对标 `--string/--not-string/--regexp`，经 config 传入）。
- **预期影响**：修复 D8；首部动态页面误判率下降。
- **工作量**：M。
- **优先级**：P1。

### 建议 8【P1】WAF 识别后自动套用推荐 tamper 重跑
- **内容**：`ScanManager` 在 `wafAgg` 汇总后（`ScanManager.js:368-374`），若存在高置信 WAF 且用户未显式配置 tamper，则将 `wafRecommend` 的推荐链写入当前扫描 config 并对已判"未命中"的点重跑一轮（受 `--level`/开关门控）。
- **预期影响**：修复 D9；WAF 目标默认配置下召回提升。
- **工作量**：M（重跑调度 + 防止请求爆炸的节流）。
- **优先级**：P1。

### 建议 9【P2】补齐缺失 tamper + 状态机重写
- **内容**：新增 `xforwardedfor`、`varnish`、`charunicodeescape`、`hexentities`、`hex2char`、`decentities`、`if2case`、`plus2concat`、`plus2fnconcat`、`equaltorlike`、`0eunion`、`dunion`、`schemasplit`、`space2morehash`；将 `space2comment`（`space2comment.js:12`）改为引号状态机（跳过字符串字面量内空格）；`randomcase` 限制只作用于 SQL 关键字（引入 keyword 表）。
- **预期影响**：WAF 绕过覆盖补齐；插件语义破坏风险下降；修复 D15。
- **工作量**：M。
- **优先级**：P2。

### 建议 10【P2】盲注提取稳定性校验（重测/投票）
- **内容**：`Extractor.extractBoolean` 对收敛字节增加二次验证（同一位置再发 1 次确认，不一致则取多数）；或对 `asciiFn(...)>mid` 判定增加与 false 基准的相似度阈值（复用 `_similar`）。
- **预期影响**：修复 D14；动态页面拖库准确性提升。
- **工作量**：S-M。
- **优先级**：P2。

### 建议 11【P2】level/risk 分级 + OR-based payload + 子句位置感知
- **内容**：config 增加 `level/risk`；level≥3 时启用更多边界与子句 payload（ORDER BY/LIMIT/HAVING 注入模板），risk≥2 追加 OR-based 布尔（`{ORIG}' OR '1'='1` 等）与时间/OOB。
- **预期影响**：修复 D7、D12；深扫能力对齐 sqlmap。
- **工作量**：L。
- **优先级**：P2。

### 建议 12【P2】URI 路径注入点 / 任意位置 `*` 标记
- **内容**：`TargetParser` 支持 URL 中包含 `*` 的路径注入点（`TargetParser.js:37-46` 前解析路径 `*`），`Detector.buildRequest`（`Detector.js:43-46`）按路径替换构造。
- **预期影响**：修复 D11；REST 场景覆盖。
- **工作量**：M。
- **优先级**：P2。

---

## 4. 核心结论（5 行）

1. **检测召回的最大短板是上下文不适配**：布尔/时间/报错模板全部按字符串上下文写死（`payloads.js`），`id=1` 这类数字参数在三技术线下基本漏检，且无 boundary 闭合探测与 UNION 类型 CAST，需按 P0 三项优先修复（建议 1/2/3）。
2. **时间盲注只检不能提**：提取通道仅布尔二分（`Extractor.extractBoolean`），时间盲注点取不出数据；DB 指纹也仅响应头+UNION 两路，无回显目标方言全错——两条 P1 补齐后链条才完整。
3. **误报控制是本项目相对亮点**：盲注统计判定（基线噪声 + z 检验 + 自适应阈值 + trace 审计）达到 sqlmap 同思路水平；但页面相似判定（LCP）与 WAF 被动识别是明显弱项。
4. **tamper 数量接近 sqlmap（62 个）但质量和联动有坑**：`randomcase` 等会破坏 `__S__/__E__` 提取标记导致拖库静默失效（P0 修复），且 WAF 识别后不自动套用 tamper。
5. **量级差距**：payload 190 条 vs sqlmap 数千条、DBMS 14 vs 40+、无 level/risk 分级、无 URI/任意位置注入点——决定了本项目在"常见场景的通用检测"够用，但在"复杂子句/多库/对抗 WAF 的深度检测"上仍有 1-2 个数量级差距。
