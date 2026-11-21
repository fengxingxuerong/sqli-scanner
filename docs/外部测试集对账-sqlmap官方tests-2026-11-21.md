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

### 3.2 覆盖缺口（未修，诚实标注）

sqlmap 报错指纹覆盖 42 方言/fork，本仓定库表 18 条。缺 26 个分支：Altibase, CockroachDB,
CrateDB, Cubrid, Doris, Drizzle, DuckDB, FrontBase, Ingres, InterSystems Cache, Mckoi, MemSQL,
MimerSQL, OpenGauss, Presto, Raima, SAP HANA, SAP MaxDB, Snowflake, Spanner, StarRocks,
Trino, Vertica, Virtuoso, YugabyteDB（+ Microsoft Access 的独立分支，本仓以 `Access` 名收录）。

**为什么不补**：
- 首版判据2 报的 14 条「报错原文未命中」经复核**大部分是假缺口**——样本截断所致：
  MariaDB/TiDB 完整报错含 `SQL syntax`、MSSQL jdbc 完整报错含 `Unclosed quotation`、
  Oracle jdbc 含 `ORA-00933`，实际全部命中。补裸品牌词反而会把技术文档页误判成报错页
  （D118「裸 SQLite3 误报」同型教训）。
- 这 26 个方言本机**无真数据库**，D310 已明确其 payload 是「静态移植、未经真机验证」。
  按真实性优先，不做无法验证的能力扩张。

## 4. 结论

- 外部测试集对账**抓到 1 个真缺陷并修复且有守卫**（D313），证明这条路有产出。
- sqlmap 的检测黄金用例（`test_techniques.py` 等）是 mock-oracle 单测，不能直接跨语言跑；
  其价值在于**报错语料与不变量思想**，本轮已用前者。
- 26 方言定库覆盖缺口是**已知边界**，非本批可真验范围，写在这里供后续批次评估。

## 5. 改动文件

- `server/src/engine/payloads/index.js`：Firebird/Informix 签名前移。
- `server/tests/sqlmapCorpus.d313.guard.test.js`：新增守卫（4 例）。
