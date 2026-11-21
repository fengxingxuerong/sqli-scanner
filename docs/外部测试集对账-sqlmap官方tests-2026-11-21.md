# 外部测试集对账：sqlmap 官方 tests / 报错语料（2026-11-21，D313）

> 用户诉求：找同类开源项目的测试文件测试本项目。
> 边界先行：sqlmap 的 `tests/*.py` 是**其内部函数的 mock 单测**（mock 掉网络/DBMS，测它自己的
> 提取/解析逻辑），跨语言直接跑必然全红，不能套用到本项目。真正可复用的是它的**数据资产**：
> `data/xml/errors.xml`（报错正则，非本仓编写的真值源）与 `tests/test_payloads_structure.py`
> 的不变量思想。本轮用前者做真代码对账。

## 1. 来源与可复现命令

| 资产 | 来源 URL | 本机落点 |
|---|---|---|
| sqlmap 报错指纹 | `https://raw.githubusercontent.com/sqlmapproject/sqlmap/master/data/xml/errors.xml` | `.box-agent-scratch/sqlmap-tests/data/errors.xml` |
| payload 结构测试 | `.../tests/test_payloads_structure.py` | `.box-agent-scratch/sqlmap-tests/` |
| 检测黄金用例 | `.../tests/test_techniques.py`（82KB） | 同上（本轮未直接复用，见 §5） |
| 对账脚本 | 本仓自写 | `.box-agent-scratch/sqlmap-tests/reconcile2.mjs` |

复现：`node .box-agent-scratch/sqlmap-tests/reconcile2.mjs`

## 2. 对账方法（真代码 vs 真语料，非 mock）

1. 从 `errors.xml` 提取 42 个方言/fork（含 Doris/StarRocks/DuckDB/CockroachDB 等新分支）。
2. **判据1 方言集合差**：与本仓 `ERROR_SIG_BY_DBMS`（18 条）按语义别名归一对账。
3. **判据2 真实报错原文**：逐条取 sqlmap 正则对应的确定报错文本，喂本仓真函数
   `SQL_ERROR_SIG`（`core/errorSig.js`）与 `dbmsFromError`（`engine/payloads/index.js`）。

⚠️ 推翻记录：首版 `reconcile.mjs` 用「正则剥字面量」自动造样本，报出「6/153 命中 (3.9%)」——
**该数字作废**。原因：转义处理把 `\d`→`d`（出现 `bORA-d` 噪声），且 `SQL syntax.*?MySQL`
被切成 `syntax.` 碎片。样本构造失真，结论不成立。改用 §2 严谨版。

## 3. 发现

### 3.1 真缺陷（已修）：定库顺序误判

`ERROR_SIG_BY_DBMS` 是「命中即停」的顺序表。宽泛签名排在精确方言前，抢先命中：

| sqlmap 官方报错形态 | 来源正则 | 修复前 `dbmsFromError` | 应为 |
|---|---|---|---|
| `Dynamic SQL Error SQL error code = -104` | `Dynamic SQL Error.{1,10}SQL error code` | **Sybase** | Firebird |
| `ODBC Informix driver error` | `ODBC Informix driver` | **SQL Server** | Informix |
| `Informix ODBC Driver SQL error` | `Informix ODBC Driver` | **SQL Server** | Informix |

危害链路：定库错 → `DBFingerprinter`/`ErrorDetector` 选错注释符与 payload 族 → 漏检。

**修法**（`server/src/engine/payloads/index.js`）：在 `dbmsFromError` 里加**精确方言优先表**
（Firebird `Dynamic SQL Error…SQL error code`、Informix `ODBC Informix driver`），
在遍历宽泛顺序表之前先查、命中即返回。**不调整 `ERROR_SIG_BY_DBMS` 数组顺序**——
初版曾把两库前移到数组高位，结果触发 `errorDetector.highfreq.test.js` 回归
（前 8 高频位被挤占，`firstDbHits` 从 ≥5 掉到 4），已撤销并改用优先表方案，零顺序回归。
守卫 `server/tests/sqlmapCorpus.d313.guard.test.js`（4 例：3 语料 + 1 防回归）。

验证：守卫修前 3 红 1 绿 → 修后 4/4 绿；缺陷注入（精确表 Firebird 签名改 `NEVER_MATCH`）
→ 1 红，备份还原 → 4/4 绿；全量定库+高频+守卫相关测试 **70/70** 绿（含回归哨兵
`errorDetector.highfreq.test.js`）。

### 3.2 覆盖缺口（D314 已补四方言，其余登记）

sqlmap 报错指纹覆盖 42 方言/fork，本仓定库表 18 条。

**D314 已补（4 个「payload 有、签名无」的方言）**：SAP MaxDB / Vertica / CUBRID / Presto。
这四方言的 payload 由 D307 装配，但此前的 `dbmsFromError` 认不出其报错 ⇒ 自动定库永远命中不到
那四套 payload，只能 `--dbms` 手动指定。

实施中实测发现**只补定库是半截链路**：定库 8/8 中、检测门仅 3/8——ErrorDetector 先用
`SQL_ERROR_SIG` 判「这是不是报错页」，判不出就走不到定库，签名再准也无效。故两处同补：

| 层 | 文件 | 补什么 |
|---|---|---|
| 检测门 | `core/errorSig.js` | 异常类名 + 独有句式（`SQL error…POS(n)`、`, Sqlstate: 42xxx, Routine:`、`[CAS INFO`、`UNION query has different number of fields`、四个 `*Exception`） |
| 定库 | `engine/payloads/index.js` 的 `PRECISE_DBMS_FIRST` | 驱动类名 + 独有句式（2→6 条） |

**不加纯驱动包名**（`com.vertica.jdbc` 这类会出现在依赖声明/技术文档里，D118 裸词误报同型）。
28 条既有语料/正常页误伤扫描零误伤。定库+高频+两批守卫 84/84 绿；
守卫 `server/tests/sqlmapDialectCoverage.d314.guard.test.js`（14 例，含检测门判据）。

**其余 20 个方言仍无签名**，在守卫的 `UNSUPPORTED` 表逐条登记理由（双向判据：缺登记红、
白名单腐烂红）：Altibase, CockroachDB, CrateDB, Doris, Drizzle, DuckDB, FrontBase, Ingres,
InterSystems Cache, Mckoi, MemSQL, MimerSQL, OpenGauss, Raima, SAP HANA, Snowflake, Spanner,
StarRocks, Trino, Virtuoso, YugabyteDB。

**为什么不全部补**：
- 首版判据2 报的 14 条「报错原文未命中」经复核**大部分是假缺口**——样本截断所致：
  MariaDB/TiDB 完整报错含 `SQL syntax`、MSSQL jdbc 完整报错含 `Unclosed quotation`、
  Oracle jdbc 含 `ORA-00933`，实际全部命中。补裸品牌词反而会把技术文档页误判成报错页
  （D118「裸 SQLite3 误报」同型教训）。
- 这些方言本机**无真数据库**，D310 已明确其 payload 是「静态移植、未经真机验证」。
  按真实性优先，不做无法验证的能力扩张；MySQL/PG 系 fork 走 `dialects.json` 的
  `aliasPatterns` 归一，不单列签名。

## 4. 结论

- 外部测试集对账**抓到 2 个真缺陷并修复且有守卫**（D313 定库顺序、D314 四方言签名缺失）。
- D314 补的不是"新能力"，而是**打通已付代价建成的能力**：D307 装配了四方言 payload，
  但定库通道认不出它们的报错，等于四套 payload 只有手动 `--dbms` 才用得上。
- 方言覆盖现由**双向判据**守护（缺登记红 + 白名单腐烂红），同类静默缺口不会再无声出现。
- 其余 20 方言是**已知边界**（多为本机无真库），逐个登记理由，不做无法验证的能力扩张。

## 5. 改动文件

- `server/src/core/errorSig.js`：D314 补四方言检测门（异常类名 + 独有句式）。
- `server/src/engine/payloads/index.js`：D313 精确优先表 + D314 扩到 6 条并 export。
- `server/tests/sqlmapCorpus.d313.guard.test.js`：D313 守卫（4 例）。
- `server/tests/sqlmapDialectCoverage.d314.guard.test.js`：D314 守卫（14 例，含检测门与双向覆盖判据）。
