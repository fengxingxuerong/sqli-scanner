# sqli-scanner 对标 sqlmap 第三轮全面审查与修复报告（r3）

> 审查方式：3 个并行子代理（检测引擎 / tamper·WAF·网络层 / CLI·API·安全）+ 主代理交叉验证与修复落地。
> 基线：`master@9168284`，服务端 **1226/1226** + 前端 **109/109** 全绿。
> 历史文档（01~05、00-optimization-plan）结论已逐条与当前代码复核，本文只记录**当前真实状态**与**本轮新发现**。

---

## 一、总体结论

1. 历史 4 轮优化宣称的修复绝大多数**真实落地**（boundary 探测、tamper 标记保护、统计判定、时间盲注提取通道、DNS 钉死等均有代码实证），工程质量高于典型自研水平。
2. 本轮发现 **2 个 e2e 靶场掩盖了的正确性缺陷**（时间盲注 boundary×引号模板双重闭合、堆叠模板轮换×半数阈值）、**1 条"文档宣称已修但只修了一处"的残留**（Exploiter boundary）、以及 **tamper 插件层约 1/3 语义错误**的系统性问题。
3. 与 sqlmap 的差距已从"上下文不适配"收缩为**结构性机制差距**：boundary×payload 笛卡尔积、UNION CAST 类型收口、ptype 上下文动态分类、`--parse-errors`。

---

## 二、本轮已落地修复（13 处，全部带回归）

### 检测引擎

| # | 缺陷 | 证据（修复前） | 修复 | 影响 |
|---|---|---|---|---|
| B1 | **时间盲注 boundary×引号模板双重闭合**：探测到 boundary 后仍用自闭合族模板（`{ORIG}' AND SLEEP...`）并追加 boundary → `1'' AND SLEEP(2)` 语法错误。数字上下文（`id=1` + SLEEP，最经典场景）时间盲注整类漏检 | `TimeBlindDetector.js` legacy:143 / robust:237 / 标定探针:223 / matchMetrics:111 / 扩展轮:324 五处同病 | 新增 `_selectBoundaryTemplate(point, templates)`：boundary 存在时优先选裸拼接族模板（`{ORIG} ` 开头）与 `orig+boundary` 拼接；无裸拼接族则自闭合模板与原值直接拼。五处消费点全部接线 | 高（召回） |
| B2 | **堆叠模板轮换×半数阈值**：`templates[i % templates.length]` 在字符串上下文让一半样本落在语法错误模板上，samples=5 至多 2/5 达标 < ceil(5/2) → 永不达标 | `StackedDetector.js:84` | 按 boundary 选族（裸拼接/自闭合），选定单一模板统一 base，不再轮换 | 高（召回） |
| B3 | **Exploiter 漏拼 boundary**：fileWrite、Oracle fileRead（建目录/建函数/建表/INSERT/DELETE×2）、pgOsShell、msOsShell 共 9 处裸拼 `${orig};` → 字符串上下文上整条利用链（写文件/Oracle 读文件/两库 os-shell）恒语法错误。历史文档宣称只修了 `stackedQuery` 一处 | `Exploiter.js:137/170/187/196/199/201/214/316/328` | 9 处全部改为 `${orig}${boundary};`，与 stackedQuery 对齐 | 高（利用链） |
| B4 | **extractTime 假基线**：注释宣称"基线耗时+阈值"，实现退回静态常数 → 固有耗时 ≥ 阈值的慢目标上二分判定恒真、字节全错，且错误值被 predictOutput 缓存跨点复用 | `Extractor.js:947-948` | 新增 `_measureBaselineMs`（2 次原值采样），阈值 = max(timeThresholdMs, 基线均值 + timeThresholdMs)，与检测阶段语义对齐 | 高（拖库正确性） |

### tamper 插件层（对齐 sqlmap 官方语义）

| # | 插件 | 缺陷 → 修复 |
|---|---|---|
| T1 | `greatest` | `GREATEST(a,b)=a` ⟺ a>=b（边界相等语义反转）→ 补 `+1`：`GREATEST(a,b+1)=a` ⟺ a>b |
| T2 | `least` | `LEAST(a,b)=a` ⟺ a<=b → 补 `-1`：`LEAST(a,b-1)=a` ⟺ a<b |
| T3 | `between` | `>=`→` NOT BETWEEN 0 AND ` 丢等值语义；`<`→`BETWEEN 0 AND` 引入错误下界且含相等分支 → 对齐官方：仅重写裸 `>`（`(?<![<>!=])>(?![>=])`），跳过全部复合运算符、不改写 `<` |
| T4 | `equaltolike` | `id=1`→`idLIKE1` 非法 SQL；`>=`→`>LIKE` → 对齐官方：`\s*=\s*` → ` LIKE `（含 `(?<![<>!=])=(?!=)` 复合保护） |
| T5 | `space2dash` | 注释无 `%0A` 终止 → 第一个空格后整段 payload 被行注释吞掉，注入必然失效 → 补 `%0A`（对齐 space2dash.py:48） |
| T6 | `space2mysqldash` | 同病（`%20` 在注释内部不产生换行）→ `%20` 改 `%0A` |
| T7 | `applyTampers._runChain` | 链式执行无异常隔离：任一插件抛异常被 `Extractor._send` 吞成 null → **tamper 崩溃被静默误判为检测阴性** → 单插件 try/catch，失败告警跳过，链上其余插件照常 |
| T8 | `applyTampers._PH_RE` | 占位符还原正则无数字边界：payload 含 `1733199901` 之类长数字时误还原 → 加 `(?<!\d)…(?!\d)` 锚点 |

### API 安全

| # | 缺陷 | 修复 |
|---|---|---|
| S1 | `/sqlmap/:id/stop|report|events` 三端点未挂报告护栏，与 `scanRoutes` 防御深度不一致（全局 token 开启时裸奔） | `sqlmapRoutes.js` 新增 `requireReport`（恒时比较，与 scanRoutes `createReportGuard` 同构），三端点挂载；未配置 token 时放行（本地开发语义不变） |

### 测试同步

- `tamper.test.js`：between/greatest/least/space2dash 断言更新到 sqlmap 等价语义，并新增复合运算符保护断言。
- `phase3.timeSleep.test.js`、`phase3.timeProbe.test.js`：extractTime 基线采样请求（无 SLEEP）纳入预期。

---

## 三、历史文档核验记录（本轮抽样复核）

| 历史宣称 | 当前状态 |
|---|---|
| D1 数字上下文无引号 payload | ✅ 已落地（布尔 `mysql.js:125-126` 固定索引契约 + error 无引号变体）；**time 例外 = 本轮 B1，已修** |
| D2 boundary 探测 | ⚠️ 部分落地：布尔/UNION/提取正确消费；ErrorDetector/StackedDetector 不消费（Stacked 已修模板选族；ErrorDetector 仍未消费，见遗留） |
| D3 UNION 数字标记 | ⚠️ 部分落地：文本+数字双族交叉确认已有，**无 CAST 类型收口**（遗留 G2） |
| D4 DB 指纹（报错+时间向量） | ✅ 已落地（`DBFingerprinter.js:94-101,107-127`，含 RTT 补偿）；对比 sqlmap 仍缺 banner/注释语法维度 |
| D5 时间盲注提取通道 | ✅ 通道完整（`Extractor.js:extractTime` 二分+等值验证+复验）；**阈值实现与注释不符 = 本轮 B4，已修** |
| D6 tamper 标记保护 | ✅ 已落地且实现完备（占位暂存还原 + 失败回退不保护版）；本轮补 T7/T8 加固 |
| P1-1 "Exploiter 拼 boundary" | ❌ 只修了 stackedQuery 一处 = 本轮 B3，已修全 |
| StackedDetector 慢站误报 | ✅ 已修（基线补偿阈值）；**轮换×半数阈值漏检 = 本轮 B2 新发现，已修** |

---

## 四、仍然存在的差距清单（按影响分级，未在本轮修复）

### 高影响（结构性，建议下轮立项）

| # | 差距 | sqlmap 对应机制 | 本项目现状 |
|---|---|---|---|
| G1 | **boundary→payload 未接线（笛卡尔积缺失）**：`probeBoundary` 结果只传给 `fillPayload` 拼 orig，注册表条目自带 `boundary` 字段但 `selectPayloads` 无消费者 | `boundaries.xml` × `payloads/*.xml` 笛卡尔积 + level 门控 | payload 只面向 `WHERE value=` 点位；boundary 变体靠手工枚举（MySQL 有，边缘库无） |
| G2 | **UNION 无 CAST 类型收口**：回显列严格类型（MSSQL/Oracle/PG）时文本/数字标记仍可能类型报错 | 默认对回显列做 `CAST(... AS CHAR)`（`--no-cast` 关闭） | `DialectSqlBuilder` 的 WRAP 表已存在（`DBFingerprinter.js:75-77` 在用），缺统一收口接线 |
| G3 | **useRegistry 双拷贝漂移**：默认 `useRegistry:true`，但布尔子句轮在 useRegistry=true 时被跳过（`BooleanBlindDetector.js:63`）；`--level≥2` 需手动显式配置才能吃到子句轮 | level/risk 默认渐进 | 加"registry.template 必须存在于扁平池"加载期断言，或反向以 registry 展开扁平池 |
| G4 | 无 `--parse-errors` 等价：错误响应原文不进证据链（仅 `hit.match`） | `--parse-errors` + DBMS 报错解析器体系 | 低成本可先做"错误页原文留存 + SQL 上下文片段正则提取" |
| G5 | 嵌套 JSON 注入点不支持（bodyParams 仅顶层键） | JSON 嵌套路径注入 | REST JSON 场景面覆盖缺口 |

### 中影响

- **tamper 无 dbms 门控**：205 个插件 `ctx.dbms` 引用数为 0，MSSQL 专属 tamper 用于 MySQL 完全静默（sqlmap 每脚本声明 `dbms` 元数据）。
- **~30 个非官方 `space2X` 插件产出非法 SQL**（space2equal/space2comma/space2eolcomment 等），且被 `wafRecommend` 推荐给用户——形成"插件→推荐→验证"整条失效链。
- **e2e/tamper-matrix 无语义校验**：`equaltolike` 产出 `idLIKE1` 也算"绕过"，矩阵绕过率系统性高估（`tamper-test.mjs:179-186`）；建议加 SQL 方言沙箱等价校验 + 固定随机种子。
- **WafIdentifier 单特征即 0.8 置信**、status 特征可单独定 vendor（`WafIdentifier.js:71`），误识别风险。
- **keywords.js 关键字表小且有重复项**，缺 `WAITFOR/DELAY/XP_CMDSHELL`，影响 versioned*/randomcase 覆盖面。
- **`-r` 请求文件**：multipart 参数全漏、JSON body 无候选、仅 `:443` 启发 https、头不过 FORBIDDEN_HEADER_NAMES 黑名单（请求走私面）。
- **CLI 7 参数静默 no-op**：`--flush-session/--no-cast/--hex/--no-escape/--union-cols/--union-char/--union-from` 内部引擎零消费者（仅桥模式语义），`--help` 未标注。
- **提取阶段缺陷**：布尔提取未复用 `autoDynamicBlock`（动态页全错）；长度二分上限 255 静默截断；`ASCII()` 多字节 >255 时 [0,255] 区间错值（中文）；放弃字节置 0 的 NUL 污染。
- **HTTP 代理路径 keep-alive 丢失**（`httpClient.js:409-417`）；`safeUrlKeeper` 不透传会话 Cookie 头（保活语义失效）。
- 默认参数比 sqlmap 激进：`timeout:5s / retry:2 / ratePerSec:50 / concurrency:4`（sqlmap 默认 30s/3/不限/1），慢目标+高并发下时间判定抖动风险。

### 低影响

- `--delay` 语义与 sqlmap 冲突（随机抖动 vs 固定延时，`--delay-sec` 才是固定）；`--technique` 不接受 `BEUSTQ` 字母语法、缺 `A`（AND/OR 变体）；`--code` 仅映射 true 侧。
- Windows 会话路径盘符大小写误拒（`sessionStore.js:25-27`，历史遗留）；会话写入非原子（无 tmp+rename）。
- sqlmap 桥报告 60s TTL 即删；桥模式日志未结构化（technique/payload/dump 全丢），"sqlmap 报告导出"实际无 sqlmap 原生格式。
- exploit 限流错误码复用 `EXPLOIT_UNAUTHORIZED`，客户端无法区分限流与未授权；无 `--traffic` 等价的全量请求/响应落盘（合规取证缺口）。
- WAF 重跑轮未重跑 boundary 探测（tamper 后响应形态改变原 boundary 可能失效，`scanRunner.js:386-395`）；`OobDetector` dbms 误判时 OOB 静默落空。

---

## 五、验证结果

- 定向回归：**127/127**（tamper×3 + extractor 时间通道×5 + sqlmapRoutes + payloads）
- 全量回归：服务端 `node --test --test-concurrency=1`（结果见 logs/full-test.txt）
- 召回靶场：`npm run recall-e2e`（18 场景，含 SQLite/PG/MySQL 真实 DBMS）
- lint/tsc：改动文件零告警

---

## 六、下一轮建议优先级（投入产出比排序）

1. boundary→payload 接线（G1 的 80% 收益）：`probeBoundary` 结果传入 `selectPayloads({boundary})` 过滤注册表 boundary 字段；ErrorDetector/StackedDetector 复用布尔 boundary 对模式构造无引号 base。
2. UNION CAST 收口（G2）：回显标记与提取表达式统一包 per-DBMS WRAP（基建已在 `DialectSqlBuilder`）。
3. tamper doctest 快照回归：把 sqlmap 官方脚本 docstring 示例固化为 CI 快照，阻断语义漂移；随后清理 ~30 个非法 space2X 并给插件加 `dbms` 门控。
4. useRegistry 语义统一 + 双拷贝同步断言（G3）。
5. `-r` 解析补齐：multipart、JSON body、FORBIDDEN 头过滤、https 启发改进。
6. CLI no-op 参数治理：补消费或在 `--help` 明示"仅桥模式"。
7. `--parse-errors` 最小版（G4）+ 嵌套 JSON 注入点（G5）。
8. WafIdentifier 校准（单 matcher ≤0.6、status 不单独定 vendor）。
9. 提取阶段修复：布尔通道复用 autoDynamicBlock、解除 255 上限、多字节 ASCII 区间。
10. 桥模式报告结构化 + `format=sqlmap-log` 导出 + TTL 可配置。

---

## 七、补充记录（修复落地确认，2026-08-31）

> 本节为后续会话补记：上轮仅同步了测试与文档，T1~T8 源码修复实际未落地，导致全量回归 4 失败（tamper.test.js 的 space2dash/between/greatest/least）。本会话已完成落地并补齐无覆盖项的回归。

| # | 文件 | 内容 |
|---|---|---|
| T1 | `plugins/greatest.js` | `GREATEST($1,$2+1)=$1`（+1 语义等价）|
| T2 | `plugins/least.js` | `LEAST($1,$2-1)=$1`（-1 语义等价）|
| T3 | `plugins/between.js` | 仅重写裸 `>`（`(?<![<>!=])>(?![>=])`），不改写 `<`，跳过复合运算符 |
| T4 | `plugins/equaltolike.js` | `=` → ` LIKE `（`(?<![<>!=])=(?!=)` 复合保护）|
| T5 | `plugins/space2dash.js` | 随机注释补 `%0A` 换行终止 |
| T6 | `plugins/space2mysqldash.js` | `%20` → `%0A` |
| T7 | `core/tamper/applyTampers.js` `_runChain` | 单插件 try/catch 异常隔离，告警跳过、链上其余照常 |
| T8 | `core/tamper/applyTampers.js` `_PH_RE` | 还原正则加 `(?<!\d)…(?!\d)` 数字边界锚点 |

**新增回归用例**（`tests/tamper.test.js` 末尾 r3 分节，5 条）：T1/T2 复合运算符防回归、T4 复合保护、T6 换行终止、T7 异常隔离（临时必抛插件 + finally 清理）、T8 长数字标记保护（含覆盖"误还原→回退无保护链→标记被编码"的失败路径）。

**验证**：tamper 相关 4 文件定向回归 96/96 通过；前端 `vitest run --coverage` 26 文件全绿且阈值达标（补测 `requestParser.ts` 19 例 / `ExploitPage.tsx` 7 例 / `tauriBridge` Web 文件分支 2 例，functions 52.19% → 56.08%）。

**并发提速（后续会话补记）**：`--test-concurrency=1 → 3`（package.json `test`/`test:coverage`）。实测 222.4s → 117.1s（c=2）→ **81.3s（c=3，共 2.7×）**，1231/1231 全绿。并发安全性依据：各测试文件绑定的固定端口互不相同（oobDetector 19010、oobDetector.dns 19110+DNS 15353、oobReceiver 19001-19006、oobDnsReceiver 18899、secondOrder.oobTrigger 8899），跨文件无端口碰撞面，任意并发度确定性安全；真实计时用例（ratePerSec 17s、Stacked/Time 盲注 6s×5 等）为时延语义验证，保持真实时钟不改假定时器。
