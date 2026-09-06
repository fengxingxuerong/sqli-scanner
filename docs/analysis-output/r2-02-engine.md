# sqli-scanner 引擎第二轮审查报告（r2-02-engine）

> 审查日期：2026-08-25 · 分支 master @ 50330f3 · 审查人：安全引擎/Node.js 架构审查（ox-alpha）
>
> 第二轮目标：① 逐项验证第一轮后已完成修复的实现质量与回归风险（不重复报已修问题本身）；
> ② 给出方言 SQL 构造器收敛重构（DialectSqlBuilder）的可执行分阶段方案；③ 核查 TimeBlindDetector
> 未知库遍历是否复用指纹时间向量结果；④ crawler 串行 BFS 的并发化与取消钩子设计；
> ⑤ 复查第一轮报告中未修中级项的现状。
>
> 验证方法：全量源码审读（detector/Extractor/Exploiter/DBFingerprinter/injection/columnGuess/
> crawler/scanRunner/sessionStore/httpClient）+ git 历史比对（74f200a 等）+ 定向测试实跑
> （stackedDetector.f19 / union.numericMarker / unionMarkerCaseInsensitive 共 11 用例全部通过，
> duration ≈18.9s）。

---

## 一、近期已修项逐个验证

### 1.1 StackedDetector 基线补偿 —— ✓ 实现正确，两处残留风险

实现核对（StackedDetector.js:59-69）：先发一次无注入基线请求测 `baselineMs`，有效阈值取
`max(thresholdMs, baselineMs + sleep*1000/2)`。判定方向正确：命中样本必须显著高于该点自身正常水位，
慢站误报 Critical（第一轮 H1）的路径已被封死；基线失败静默退化为纯配置阈值，不阻断。证据串同时
回显基线值与配置阈值，可审计性好。实测 5 个 stacked 用例通过（MySQL/PG/MSSQL 命中、Oracle 跳过、
无延迟不误报）。

残留风险（新发现，非重复报）：

- [StackedDetector.js:69 中] **max() 语义使配置阈值仍为绝对上限门**：当用户配置
  `timeThresholdMs ≥ sleepSecs*1000`（如默认阈值 1500ms 没问题，但配 3000ms + sleep=2s 时，
  SLEEP(2) 的总耗时 ≈2000ms < 3000ms）时所有样本永不达标 → 系统性漏报。补偿只加了下限没管上限，
  建议 `effectiveThreshold = min(max(thresholdMs, baselineMs + sleep*500), baselineMs + sleep*1000 - ε)`
  或至少在 evidence 中提示「阈值高于预期延迟」。
- [StackedDetector.js:62-66 低] 基线为**单样本**：一次网络抖动抬高 baselineMs → 阈值虚高 → 漏报方向
  （安全方向，可接受）；反之抖动低谷不会造成误报（还有 sleep*500 余量）。可选：2 次取均值。
- [server/tests/stackedDetector.f19.test.js 低] **缺慢站基线补偿的回归用例**：现有 5 例均未覆盖
  「基线 ≥ 阈值的慢站上不误报」这一修复核心场景，回归防护缺位。建议补一发 mock 慢基线的负例。

### 1.2 InlineQueryDetector 反射门控 —— ✓ 实现正确

实现核对（InlineQueryDetector.js:44-58）：命中条件（test 含标记 && base 不含）成立后才追加
REFLECTION_PROBE 纯文本探针，探针同样被回显即拒绝并写明拒绝原因。门控顺序正确（只在候选命中后
多花 1 个请求，未命中路径零额外成本）；PROBE 常量与 INLINE_MARKER 无公共子串，大小写不敏感比较
与 D6 口径一致；数值型参数（test=`(SELECT '…')` 整串会被反射型页面原样带回）同样被门控拦截。
第一轮 H2 的误报路径关闭。

残留（低）：若目标对反射值做 HTML 编码（`'`→`&#39;` 等），PROBE 匹配失败 → 门控放行 → 编码型反射
页面仍可能误报。概率低（多数反射型页面同时回显原始文本），可在 PROBE 中混入无特殊字符的纯字母数字
串（现已满足）并接受该残余。

### 1.3 DBFingerprinter 时间定库 RTT 补偿（5cfaef1）—— ✓ 实现正确

实现核对（DBFingerprinter.js:170-189）：`_fingerprintByTime` 新增 `baselineRtt` 入参，有效阈值
`effThreshold = baselineRtt + (config.fingerprintTimeThresholdMs ?? 800)`；baselineRtt 由
fingerprint() 主流程在基线请求处实测传入。判定方向正确：延时信号必须显著超出该目标正常往返，
高 RTT 网络下第一个向量误命中的历史 bug（第一轮 §七-4）路径关闭。TIME_VECTORS 各向量对非注入点
快速返回、命中即停，请求预算 5 条有界。

残留风险：
- [DBFingerprinter.js:177 低] baselineRtt 为单样本实测：网络抖动低谷 → effThreshold 偏低 →
  仍有小概率把「慢响应非注入」判成某库（方向仍是方言判错级联，但概率大幅降低）。可选：基线测 2 次取 max。
- [DBFingerprinter.js:175-176 低] sleepSec=1 与 thresholdMs=800 的默认组合对 SQLite
  LIKE(RANDOMBLOB) 这类 CPU 近似延迟向量偏紧（延迟量取决于 blob 大小估算而非精确秒），
  实际命中率待真实环境验证（代码注释亦如此声明）。

### 1.4 _colGuessCache 跨目标串数据（H4）—— ✓ 实现正确

实现核对（Extractor.js:1136-1150）：cacheKey 统一经 `colGuessScopeKey(target, pointId)` =
`${target.baseUrl}|${pointId}`；三个消费点全部改用（Extractor.js:421 / UnionDetector.js:106 /
DBFingerprinter.js:95），全仓 grep 核实无遗漏调用方。scanRunner.js:64 每扫描开始
`_colGuessCache.clear()` 兜底进程级隔离。「同路径同名参数跨目标复用列数」的污染路径关闭。

残留（低）：key 用原始 baseUrl 字符串拼接，`http://x/a` 与 `http://x/a/` 视为不同作用域——
只导致缓存 miss 多一次猜列请求，无正确性影响。

### 1.5 UNION 数值回显列方言 CAST + wrapMarker 共享（74f200a）—— ✓ 实现正确，一处未收敛

实现核对（injection.js:139-178 discoverEchoColumnsDetailed）：文本标记族探测失败后自动落
NUM_MARKER 数字族双探针交叉确认（hitsA ∩ bodyB.includes），返回 { cols, numericCols, style,
evidencePayload }；UnionDetector.js:111-128 消费时保持「echoCols=可回显文本列」语义——纯数值
命中 confirmed=true 但置空 echoCols，提取阶段不会被误导到无法回显文本的列。大小写不敏感由调用方
`/__S__(.*?)__E__/is` 口径保证（DBFingerprinter.js:134 同款）。union.numericMarker /
unionMarkerCaseInsensitive 用例实跑通过。

残留（中→并入 §五复查）：injection.js 全文无 fromDummy 引用——UNION 探测 payload 在
Oracle/DM8（需 FROM dual）、DB2/Derby（SYSDUMMY1）等库上缺伪表 FROM，严格语法库上文本族与
数值族两路探针都会直接语法失败 → 该类目标 UNION 检测系统性失效。第一轮已报，本轮确认未修，
且 74f200a 重写该函数时 WRAP 已收敛而 fromDummy 未收敛，归入 §二重构方案 P0 第一刀。

### 1.6 Exploiter Oracle 文件读 O(n²) 物化（5cfaef1）—— ✓ 实现正确

实现核对（Exploiter.js:198-224）：sqliload() 整文件加载从「每段重跑」改为先 INSERT 物化到
GLOBAL TEMPORARY TABLE SQLI_DUMP（ON COMMIT PRESERVE ROWS 会话级），分段循环只读
DBMS_LOB.SUBSTR(content,...)，N 段 = 1 次全文件 I/O + N 次段读，O(n²) → O(n)。物化失败时
回退读空表 → seg=null → break → ok:false，失败语义诚实；结束后 DELETE 清理临时行。
exploiter.test.js 断言已同步更新。

残留（低）：单文件 400KB 硬编码上限（off ≤ 400000）未参数化；GTT 建表冲突依赖 catch 忽略——
GTT 为会话私有对象，并发扫描互不干扰，语义核实无误。

### 1.7 PG UDF 方言类型拆分（57715d1）—— ✓ 实现正确

UDF_LIB（Exploiter.js:458-465）MySQL 用 INTEGER/STRING、PostgreSQL 用 integer/text，
CREATE FUNCTION 模板按方言各自生成（PG 带 OR REPLACE + LANGUAGE C STRICT）。注释明确记录了
历史 bug 成因，防回归意识好。

### 1.8 MSSQL 分页 ORDER BY 补齐（57715d1）—— ✓ 实现正确，拷贝并存

Exploiter.js:62 buildStackPageSql 的 OFFSET 分支补 `ORDER BY (SELECT NULL)`；与
Extractor.js:108 SYS_QUERIES['SQL Server'].data 的写法逐字一致。功能正确，但同一分页逻辑
两份手工拷贝并存是 §二 PaginationBuilder 的收敛对象。

### 1.9 sessionStore 锁清理（第一轮 §七-7 声称已修）—— ✗ 修复无效，问题仍在

server/src/core/sessionStore.js:40-45：`fileLocks.set(filePath, next.catch(() => {}))` 存入的
是一个新建 Promise；清理判断 `fileLocks.get(filePath) === next.catch(() => {})` 再次调用
`.catch(() => {})` 又生成全新 Promise 对象 → 严格相等恒 false → delete 永不执行。与第一轮
指出的 bug 同构（每次 `.catch()` 都返回新引用这一根因未消除），本次只是换了写法。锁条目仍随
写入次数无界增长（进程级内存泄漏）。一行修法：把 caught promise 提为局部变量再存取同一引用：

```js
const caught = next.catch(() => {});
fileLocks.set(filePath, caught);
next.then(() => { if (fileLocks.get(filePath) === caught) fileLocks.delete(filePath); }, () => {});
```

---

## 二、方言 SQL 构造器收敛重构方案（DialectSqlBuilder）

### 2.1 现状盘点：方言知识散落六处

| 位置 | 内容 | 漂移实证 |
|---|---|---|
| DBFingerprinter.js WRAP:12-38 | 18 库标记包裹 | 单一事实源（P1-10 收敛过），但经 Extractor re-export 二跳引用 |
| Extractor.js escCols:47-63 | 6 组标识符引号规则 | 方言分组与 WRAP 的分组口径不一致（如 ClickHouse 归反引号组） |
| Extractor.js SYS_QUERIES | 聚合/分页/系统表模板 | MSSQL 分页刚修，与 Exploiter.js:62 手工拷贝并存 |
| Exploiter.js buildStackPageSql / OS_SHELL / UDF_LIB | 分页/命令包装/UDF 类型 | 第一轮 MSSQL ORDER BY、PG UDF 类型两起事故均源于此层拷贝 |
| payloads/index.js TIME_VECTORS:309-315 | 5 库延时原语 | 与 TimeBlindDetector.TIME_DBMS_ORDER:11、DBFingerprinter.HIGH_FREQ_DBMS:42 三张清单并行维护 |
| payloads/index.js PAYLOADS[*].time/error | 检测模板 | 同库延时原语与 TIME_VECTORS 重复声明 |

三张 DBMS 候选清单语义相近（候选优先级）、内容不一（10 库 vs 5 库 vs 5 库），新增一个方言要同步
4-6 处——这正是第一轮两起「同一逻辑第二份拷贝漂移」事故的结构性根因。

### 2.2 目标形态

新建 `server/src/engine/dialect/sqlBuilder.js`：零依赖纯函数模块（禁止 import 引擎其它文件，
从根上切断 Extractor↔DBFingerprinter↔UnionDetector 循环导入三角），导出：

- `quoteIdent(dbms, name)`：表驱动收编 escCols 六组引号规则；
- `wrapMarker(dbms, expr)`：吸收 WRAP 全部 18 分支（DBFingerprinter 改委托 + re-export 保兼容）；
- `dummyFrom(dbms)`：自 DBFingerprinter.fromDummy 平移；
- `pageClause(dbms, offset, limit, orderBy?)`：LIMIT/OFFSET | OFFSET-FETCH(强制 ORDER BY) | ROWNUM 三态；
- `aggExpr(dbms, exprs, colSep, rowSep)`：GROUP_CONCAT / STRING_AGG / LISTAGG / group_concat(||) 四态，
  分隔符常量（CHAR(31)/CHR(31)/0x1F…）一并收编，消除 Extractor 与 Exploiter.deepDump 的双份定义；
- `sleepPrimitive(dbms)` + `DIALECT_CANDIDATES`：吸收 TIME_VECTORS，TIME_DBMS_ORDER 与
  HIGH_FREQ_DBMS 合并为一张按能力筛选的有序候选表派生。

### 2.3 分阶段落地（每阶段独立可合入，全量测试绿为出卡条件）

- **P0（约 0.5 天）**：平移 quoteIdent/wrapMarker/dummyFrom 三个纯函数，旧符号全部改委托调用，
  行为零变化；现有 dbmsExtend/union 用例作回归网。唯一允许的行为修复：discoverEchoColumnsDetailed
  的 UNION 探针拼 dummyFrom(dbms)，顺带修掉 §1.5 遗留的 Oracle 缺 FROM 问题。
- **P1（约 1 天）**：pageClause 替换 SYS_QUERIES[*].data 分页段与 buildStackPageSql，删除
  Exploiter 手工分页拷贝；新增 per-dialect 分页快照测试（5 库 × offset/limit 组合）。
- **P2（约 1 天）**：aggExpr 替换聚合段，dumpData/deepDump 分隔符经单一常量表对齐；
  GROUP_CONCAT 1024 截断在此层统一处理（会话变量前置或长度预检），清偿 §五 M4。
- **P3（约 0.5 天）**：sleepPrimitive + DIALECT_CANDIDATES 收编三张清单；TimeBlindDetector 与
  DBFingerprinter 改从同一来源取候选序，§三的复用建议在该结构上落地。

护栏：sqlBuilder.js 单独设 CI coverage 卡点（分支全覆盖）；每个导出函数配 per-dialect 快照测试；
eslint no-restricted-imports 禁止其反向 import 引擎模块。

---

## 三、TimeBlindDetector 指纹时间向量复用核查

结论：**复用链路存在且生效，但有两条旁路损耗。**

生效路径：DBFingerprinter._fingerprintByTime 命中 → 返回 dbms → scanRunner.js:171-209 将
detectedDbms 写入 ctx.dbms（并 point.dbms）→ TimeBlindDetector.detect(ctx) 走 L31-38 已知库
直达分支，不再进入 L42-46 的 5 库遍历；fpCache（scanRunner.js:144）按目标缓存指纹 Promise，
多注入点只跑一次指纹。第一轮「未知库遍历 ~80s 纯 sleep 墙钟」在指纹时间通道命中的场景已被消解。

旁路损耗：

1. [TimeBlindDetector.js:42-46 中] 指纹四通道（header/UNION 回显/报错/时间）全部 miss 时
   （dbms=null，常见于无回显 + 报错特征被 WAF 抹除的目标），检测器仍串行遍历 TIME_DBMS_ORDER，
   最坏 ~80s 墙钟原样保留。建议：_fingerprintByTime 即使未达置信也返回「疑似库」提示
   （如某向量耗时 > effThreshold*0.6 记 timeSuspect），scanRunner 把疑似库排到检测器候选序首位，
   命中其余 4 库遍历可整段跳过。
2. [DBFingerprinter ↔ TimeBlindDetector 低] 指纹时间通道命中后，检测器对该库重跑全套延迟采样
   （legacy 3 基线 + 4 注入 / robust 更多）——确认逻辑本身合理，但指纹阶段已付费的耗时观测
   （t0/elapsed）被直接丢弃、未并入 result.trace，前端盲注时间线少一段真实数据。低成本改进：
   指纹时间样本经 ctx 旁路透传给检测器 trace。
3. [低] 三张候选清单集合不一致（§2.1）：HIGH_FREQ_DBMS 含 MariaDB/TiDB/DM8 等 10 库而
   TIME_DBMS_ORDER 仅 5 库——正向场景（指纹判定 MariaDB/DM8 后直达分支）没问题；反向场景
   （指纹全 miss、检测器遍历定库）永远试不到 DM8/Sybase 等库的独有延时原语。P3 收编后自然消除。

## 四、crawler 串行 BFS 并发化与取消钩子设计

现状（crawler.js:124-151）：逐 await 取页，maxTotalPages=50 上限下墙钟 = ΣRTT（500ms RTT 约
25s+）；无并发也无取消钩子，stop 扫描后爬虫仍会跑完剩余队列。

设计方案（保持 BFS 深度语义不变，层内并发）：

1. **层内并发池**：每层 frontier 以固定并发 p（config.crawlConcurrency ?? 4）取页；池实现沿用
   Detector.sendConcurrent 思路（游标取号、结果保位）。maxPagesPerDepth/maxTotalPages 用
   「派发前同步检查计数器」控制，超限不再派发新任务。
2. **并发去重竞态**：现实现 visited.add 在串行取页前执行；并发化后必须在**派发时同步占坑**
   （check-and-add 一个同步段完成），防止同层两个 worker 抓同一 URL；next/frontier 组装放在
   全层 Promise.allSettled 之后——深度语义与现状完全一致。
3. **取消钩子（两阶段）**：
   - 阶段一（协作式，改动最小）：crawl(opts) 增加 shouldCancel 回调（TargetParser 调用方传
     () => sm 扫描态检查），每次取页前检查，true 即清空 frontier 返回已抓页面；
   - 阶段二（硬中断）：httpClient.request 目前无 AbortController/signal 通道（core/httpClient.js
     全文 grep 核实仅超时 ECONNABORTED 判断），需在 HttpClient 增加 signal 透传至底层 HTTP 栈，
     crawler 持有 AbortController 在 cancel 时 abort 在途 GET。该能力同时是 H3 取消传播收尾
     的公共底座，建议与 H3 合并一个 PR 实施。
4. **测试**：mock client 断言 inflight ≤ p；中途置 cancelled 断言不再发出新请求；
   同 URL 双 worker 派发竞态（visited 占坑）用例。

---

## 五、第一轮未修中级项复查（逐项现状）

已修且本轮验证通过（详见 §一）：StackedDetector 基线补偿 ✓ · InlineQueryDetector 反射门控 ✓ ·
DBFingerprinter 时间定库 RTT ✓ · _colGuessCache 跨目标隔离 ✓ · UNION 数值标记方言 CAST ✓ ·
Oracle 文件读 O(n²) ✓ · PG UDF 类型 ✓ · MSSQL 分页 ORDER BY ✓ · sessionStore 写原子性 ✓。

仍未修（本轮复核源码确认）：

- [BooleanBlindDetector.js:506-512 中] 大 body「首尾采样」近似判定原样保留：>64KB 且长度差在
  容差内时中段差异不可见，模板化大页面的假条件仍可能判相似 → 漏报边界。chunkSimilarity 兜底只接
  在小 body 路径（L519），大 body 快速路径 return true 前无分块校验。
- [Extractor.js:530 中] dumpData 末页误判未修：rowStrs 经 filter(Boolean) 后与 lim 比较，
  全 NULL 行页仍触发提前终止；GROUP_CONCAT 1024 截断亦未见处理（归 §二 P2 统一解）。
- [Detector.js:382-383 中] probeBoundary 锚点模式判据未动：matchAnchors 对所有闭合候选返回同一
  结果，--string 配置下首个空前缀恒命中。注意 matchMetrics/_matchAnchorsPair 是检测判定层新增，
  与 boundary 探测层的旧问题是两回事，勿因新增代码误判已修。
- [columnGuess.js:26 中] 二分判据仍假设「错误页必 status>=500 或长度腰斩」：WAF 统一返回 200
  错误页的目标上单调性失真依旧。
- [injection.js 中] discoverEchoColumns 族无 fromDummy → Oracle/DM8/DB2 UNION 探测语法失败
  （§1.5，升级为 §二 P0 第一刀）。
- [core/httpClient.js + scanRunner.js 中] H3 取消传播仍是协作式检查点（point 边界查 s.cancelled），
  在途请求不可中断；AbortSignal 通道缺席（§四阶段二给出落点）。
- [core/sessionStore.js:43-45 中] 锁条目清理修复无效（§1.9，一行局部变量可解）。

## 六、严重级别汇总（本轮）

### 高（0 项新增）

第一轮四个高危的修复实现质量良好：H1/H2 的误报路径、H4 的跨目标缓存污染均已正确关闭；
近期七项引擎修复核心逻辑逐个验证无误，无新增高危回归。唯一「修复无效」项（sessionStore 锁泄漏）
危害方向为内存增长而非正确性/误报漏报，降级为中级。

### 中（7 项）

| # | 位置 | 问题 |
|---|---|---|
| M1 | sessionStore.js:43-45 | 锁清理比较恒 false，修复无效，锁 Map 仍无界增长 |
| M2 | TimeBlindDetector.js:42-46 | 指纹全 miss 时 5 库串行遍历 ~80s 墙钟原样保留（建议 timeSuspect 旁路） |
| M3 | StackedDetector.js:69 | 配置阈值 ≥ sleep 时长时 max() 上限门系统性漏报（§1.1 残留） |
| M4 | Extractor.js:530 | dumpData 末页误判 + GROUP_CONCAT 截断未修（遗留） |
| M5 | injection.js discoverEchoColumns* | Oracle/DM8/DB2 缺伪表 FROM，严格语法库 UNION 探测失效（遗留，P0 修） |
| M6 | BooleanBlindDetector.js:506-512 | 大 body 头尾采样漏报边界（遗留未修） |
| M7 | Detector.js:382-383 | probeBoundary 锚点模式恒命中空前缀（遗留未修） |

### 低（9 项）

StackedDetector 单样本基线抖动 · stacked 慢站补偿负例回归用例缺失 · InlineQuery HTML 编码反射残余 ·
_colGuessCache key 未归一化 trailing slash · 循环导入三角未解（_colGuessCache 仍在 Extractor，
随 §二 P0 自然消除）· oracleFileRead 400KB 硬编码上限 · 指纹时间通道观测数据未入 trace ·
三张 DBMS 候选清单集合不一致（P3 消除）· SQLite LIKE 延迟向量阈值组合待真实环境验证。

### 总体结论

第二轮验证结论正面：近期引擎修复（74f200a / 5cfaef1 / 7ca2add 系列）实现与注释一致、方向正确、
性能修复无副作用，回归防护基本到位（仅缺 stacked 慢站负例一例）。结构性债务集中且清晰——
方言 SQL 知识散落六处、三张 DBMS 清单并行、循环导入三角；§二的四阶段 DialectSqlBuilder 方案约
3 天可分批落地，并顺带清偿 M4/M5 两个遗留中级项。crawler 并发化（§四）建议与 H3 取消传播的
AbortSignal 底座合并为一个 PR 实施。
