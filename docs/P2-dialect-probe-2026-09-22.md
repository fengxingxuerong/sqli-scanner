# P2 方言审计取证：H2 / HSQLDB / Derby 真引擎实测（2026-09-22）

> **取证方式**：`e2e/multi-engine-lab` 的 `EngineBridge`（真 JDBC：H2 2.x / HSQLDB 2.x / Derby 10.16，
> Java 21）。把 `buildStackPageSql` 与 `SYS_QUERIES.*.data` 生成的**真实 SQL 原样投递**给引擎，
> 记录引擎自己的返回。**不采信文档推测，不采信组件自报。**
>
> 复现命令：
> ```bash
> ENGINE_JARS="D:\engines\jars\h2.jar;D:\engines\jars\hsqldb.jar;D:\engines\jars\derby.jar;D:\engines\jars\derbyshared.jar" \
>   node e2e/multi-engine-lab/probe-dialect-sep4.mjs
> ```

## 一、结论速查

| # | 断言 | 引擎 | 结果 | 引擎原话 |
|---|---|---|---|---|
| A1 | H2 接受 `SEPARATOR CHAR(30)` | H2 | ✅ 接受 | （执行成功，返回 `1␟user1␟admin…`） |
| A2 | H2 接受 `SEPARATOR CHAR(10)` | H2 | ✅ 接受 | — |
| A3/A4 | H2 接受 `SEPARATOR ','` / 省略 | H2 | ✅ 接受 | — |
| B1 | HSQLDB 接受 `SEPARATOR CHAR(30)` | HSQLDB | ❌ **拒绝** | `unexpected token : CHAR required: a quoted string` |
| B2 | HSQLDB 接受 `SEPARATOR ','` | HSQLDB | ✅ 接受 | 返回 `1␟user1,2␟user2` |
| B3 | HSQLDB 接受省略 SEPARATOR | HSQLDB | ✅ 接受 | 同上（默认逗号） |
| B4 | HSQLDB 接受两参 `GROUP_CONCAT(x, y)` | HSQLDB | ❌ **拒绝** | `unexpected token : , required: )` |
| B10 | HSQLDB 接受反引号标识符 | HSQLDB | ❌ **拒绝** | `unexpected token:` |
| C3 | Derby 有 `GROUP_CONCAT` | Derby | ❌ **不存在** | `'GROUP_CONCAT' is not recognized as a function or procedure.` |
| C4 | Derby 有 `LISTAGG` | Derby | ❌ **不存在** | `'LISTAGG' is not recognized as a function or procedure.` |
| C5 | Derby 支持 `XMLELEMENT(NAME a, x)` | Derby | ❌ **拒绝** | `Syntax error: Encountered "a"` |
| C-New | Derby 的 `CHAR(31)` 是控制字符 | Derby | ❌ **不是** | 返回字符串 `"31         "`（11 字符，右填充） |
| C-VARCHAR | Derby 接受 `CAST(x AS VARCHAR)`（无长度） | Derby | ❌ **拒绝** | `Syntax error: Encountered ")"` |
| C-CHAR | Derby 接受 `CAST(x AS CHAR)` | Derby | ✅ 接受 | — |
| D7-doc | MonetDB 引号标识符形态 | MonetDB | **未实测** | 官方手册只定义**双引号**（`"encapsulation with double quotes"`），未定义反引号 |

## 二、逐条证据（引擎原始返回）

### B1 —— HSQLDB 拒绝表达式分隔符（**与 MySQL 同类缺陷，实锤**）

```
SQL : SELECT GROUP_CONCAT(CONCAT_WS(CHAR(31), ID, NAME) SEPARATOR CHAR(30)) FROM T2
-> unexpected token : CHAR required: a quoted string
```

错误里 `required: a quoted string` 是 HSQLDB 语法定义自述：SEPARATOR 的操作数**只接受引号字符串字面量**。
与 MySQL 的 `SEPARATOR_SYM text_string`（MySQL Bug #64600）是**同一类**限制，两个库独立命中同一坑。

对照 B2/B3 证明「GROUP_CONCAT 本体可用、CONCAT_WS 可用、表名可用」，失败点被精确锁定在
**SEPARATOR 的操作数形态**，不是其他任何因素。

### B10 —— HSQLDB 反引号非法

```
SQL : SELECT `ID` FROM `T2`
-> unexpected token:
```

`EngineBridge.open("hsqldb")` 用的是 `jdbc:hsqldb:mem:lab`（**无 MySQL 兼容模式**），
所以反引号不是标识符引用符。而 `DialectSqlBuilder.escCols` 把 HSQLDB 归进**反引号组**（第 129 行）。

### C-New —— Derby 的 `CHAR()` 返回字符串不是控制字符

```
SQL : SELECT CHAR(31) FROM users
-> [["31         "],["31         "],["31         "]]
```

不是 ASCII 31（`␟`），而是 **11 字符字符串 `"31"` + 9 空格**。说明 Derby 里 `CHAR(n)` 被解析为
「定长字符字面量/类型转换」，**不产生控制字符**。所以 Derby 的拖库行/列分隔符方案根本无从建立
（`CHAR(31)`/`CHAR(30)`/`CHAR(10)` 全部退化成字符串 `"31"/"30"/"10"`）——**Derby 拖库通道结构性不可用**。

### C3/C4 —— Derby 无字符串聚合函数

```
SELECT GROUP_CONCAT(name) FROM users  -> 'GROUP_CONCAT' is not recognized as a function or procedure.
SELECT LISTAGG(name, ',') FROM users  -> 'LISTAGG' is not recognized as a function or procedure.
```

Derby 是纯 SQL 标准库，二者皆无。官方等价物是 `XMLAGG`/`XMLSERIALIZE`，但本机引擎对
`XMLELEMENT(NAME a, x)` 报语法错（见 C5），即**标准写法在 Derby 上也需调整**。

## 三、未取证（诚实标注）

- **MonetDB 的两参 `group_concat`**：`SYS_QUERIES.MonetDB.data` 用 `group_concat(x, CHAR(30))` 两参形态 + `CONCAT_WS`。
  本机无 MonetDB 引擎/驱动 → **无真机证据**。MonetDB 官方文档称 `group_concat` 两参形态合法，
  但**未实测**。（注：HSQLDB 的两参形态被实测拒绝，说明「两参形态」不能跨库类推。）
  → **标识符引号一项已另行取证（见「四·补2」），但那属文档证据，非引擎实测。**
- **DB2 / ClickHouse / Firebird / Informix / Sybase / Oracle / DM8 / Access**：同理无本机引擎。
  Oracle/DB2/ClickHouse/Firebird 的修复依据为各自官方文档与已知 Bug 库，已在代码注释标注。
- **buildStackPageSql 的 `default` 分支覆盖面**：`default` 会命中
  `H2 / HSQLDB / Derby / DB2 / ClickHouse / Firebird / Informix / MonetDB / Oracle / DM8 / Sybase / Access`
  —— 已实测 H2 可用、HSQLDB/ Derby 不可用；其余无引擎。

## 四、由本轮取证推出的缺陷清单（已全部修复）

| ID | 位置 | 缺陷 | 证据强度 | 处置 |
|---|---|---|---|---|
| **D1** | `Exploiter.buildStackPageSql` `default` 分支 | 对 HSQLDB/Derby/DB2/ClickHouse/Firebird/Informix/MonetDB/Sybase/Access/Oracle/DM8 一律生成 `GROUP_CONCAT(x SEPARATOR CHAR(10))`（MySQL 语法套 12 个方言） | **引擎实测**（HSQLDB 拒绝 / Derby 无该函数） | HSQLDB 独立 case 修好；H2 独立 case 保留；其余**返回 null 诚实降级** |
| **D2** | `SYS_QUERIES.HSQLDB.data` | `SEPARATOR CHAR(30)` → HSQLDB 语法错，HSQLDB 拖库恒失败 | **引擎实测** | 改 `SEPARATOR U&'\001E'`，**真机复验通过** |
| **D3** | `SYS_QUERIES.Derby.data` | `GROUP_CONCAT(...)` → Derby 无此函数 | **引擎实测** | `data: null` 诚实降级 |
| **D4** | `DialectSqlBuilder` 的 `escCols` / `quoteCol` / `tableRef`（**三处独立判定**） | HSQLDB 误归反引号组 → HSQLDB 上所有列/表引用语法错 | **引擎实测** | 三处全部改双引号，**真机复验通过** |
| **D5** | `DialectSqlBuilder.nnExpr`（Derby 分支） | `IFNULL(CAST(x AS VARCHAR),'')` → Derby 报 `Cannot convert types 'INTEGER' to 'VARCHAR'` | **引擎实测** | 改 `COALESCE(CAST(x AS VARCHAR(4000)),'')` |
| **D6** | Derby 整条拖库链路 | Derby 无控制字符函数（`CHAR(31)` 返回字符串 `"31"`）+ 无字符串聚合函数 → 结构性不可用 | **引擎实测** | 诚实降级 `data=null`（与 Access/Informix 同处置） |
| **D7** | `DialectSqlBuilder.escCols`（MonetDB 分支） | MonetDB 误归反引号组，与同一语句里 `tableRef` 的双引号表名**自相矛盾** | **官方文档 + 静态自洽**（本机无引擎，强度低于 D1–D6） | 移出反引号组 → 双引号，**缺陷注入复验通过** |

### 复验（修复后真机再投递）

| SQL 来源 | 修复前 | 修复后 |
|---|---|---|
| `SYS_QUERIES.HSQLDB.data` | `unexpected token : CHAR required: a quoted string` | ✅ **执行成功** |
| `buildStackPageSql('HSQLDB', …)` | `unexpected token : required: AS` | ✅ **执行成功** |
| `SYS_QUERIES.H2.data` | ✅ 执行成功 | ✅ 执行成功（未回归） |
| `buildStackPageSql('H2', …)` | ✅ 执行成功 | ✅ 执行成功（未回归） |
| `SYS_QUERIES.Derby.databases` | ✅ `["APP"]` | ✅ `["APP"]`（保留） |
| `SYS_QUERIES.Derby.tables` | ❌ `'GROUP_CONCAT' is not recognized…` | 降级 `null` → 返回 `[]` |
| `SYS_QUERIES.Derby.columns` | ❌ 同上 | 降级 `null` → 返回 `[]` |
| `SYS_QUERIES.Derby.data` | ❌ 同上 | 降级 `null` → 返回 `[]` |
| `buildStackPageSql('DB2'/'Oracle'/…)` | 生成必然报错的 SQL | 返回 `null`（调用方给出准确不支持错误） |

复验脚本：`e2e/multi-engine-lab/verify-dialect-templates.mjs`（可复现，退出码 0 = 全通过）。

---

## 四·补、第五批：枚举空查询「运行时抛错」而非返回空列表（本轮附带发现）

审计 Derby 降级时，发现一个**与 Derby 无关的既有缺陷**（Access 早已踩中，只是没人跑过）：

`Extractor.enumerateTables` / `enumerateColumns` 的写法是：
```js
const q = resolveSysQueries(edb, ctx.dbmsVersion)?.tables(db);   // ← 只保护对象
```
可选链 `?.` 保护的是 **`resolveSysQueries(...)` 这个对象**，而 `tables` **属性本身为 null 时**
（`SYS_QUERIES.Access.tables === null`）表达式变成 `null(db)` → **抛 TypeError**：

```
new Extractor().enumerateTables({dbms:'Access', point:{}, config:{}})
-> TypeError: resolveSysQueries(...)?.tables is not a function
```

即：「把枚举能力标记为不支持（null）」与「运行时返回空列表」**错配**——调用方以为拿到 `[]`，
实际拿到异常。对照 `enumerateDatabases` 写的是 `if (q == null) return []`，语义正确，
说明这是**三处同类代码里漏改的两处**。

**修法**：改用 `?.tables?.(db)`（属性可选 + 调用可选），与 `enumerateDatabases` 对齐。

**缺陷注入复验**（本轮实际执行）：把 `?.tables?.()` 改回 `?.tables()` → 目标 3 个用例变红
（24 pass / 3 fail），其余 24 个保持绿 → 证明该测试确实钉住了这个行为；恢复后 27/27 绿。

> **教训**：`?.foo(x)` 与 `?.foo?.(x)` 语义不同。前者只防 `foo` 所在**对象**为 null，
> 不防 `foo` **自身**为 null。凡「字典值可能是 null」的调用点，都要用双可选链。

---

## 四·补2、第六批：MonetDB 标识符引号自相矛盾（**文档取证 + 静态自洽性**，非引擎实测）

把全部方言的 `data` 模板渲染成矩阵后，一个**无需引擎、纯静态即可发现**的矛盾浮现：

```
MonetDB.data = SELECT group_concat(CONCAT_WS(CHAR(31), IFNULL(CAST(`id` AS CHAR),''),...), CHAR(30))
               FROM (SELECT `id`,`name` FROM "users" LIMIT 5 OFFSET 0) __p
                                                  ^^^^^^^ 表名=双引号
                        ^^^^ 列名=反引号
```

**同一条语句里，表名用双引号、列名用反引号** —— 至少有一种必错。两条独立证据都指向「列名的反引号是错的」：

1. **内部自洽性**：`tableRef('MonetDB', …)` 走 `default` 分支产出 `"users"`（双引号），
   而 `escCols` 把 MonetDB 归进反引号组。二者只能有一个对。
2. **官方文档**（决定性）：MonetDB 手册《Lexical Structure · Identifiers and Keywords》原文：
   > "Users can overrule the interpretation of an identifier as a keyword by **encapsulation with double quotes**…
   >  Names are used to designate database objects. In that role, they are by default case in-sensitive
   >  **unless encapsulated by double quotes**."

   —— MonetDB 词法里**引号标识符只有双引号一种形态**，未定义反引号。这与 HSQLDB（D4）是**同一类缺陷**。

**处置**：`escCols` 把 MonetDB 从反引号组移出 → 双引号组（与 HSQLDB 同修）。
`quoteCol` / `tableRef` 原本对 MonetDB 已是双引号，无需改。修后 MonetDB 三处引号**全部双引号**，自洽。

**诚实边界**：本机**无 MonetDB 引擎**（且无 Docker），此修复**未经真机执行验证**，
仅基于官方文档 + 静态自洽性。若日后接入 MonetDB 真引擎，须按 HSQLDB 的方式复验后再下最终结论。
**这属于「依据文档推断」，强度低于前五批的「引擎实测」——不得与前五批并列宣称同等级。**

**缺陷注入复验**（本轮实际执行）：把 MonetDB 移回反引号组 → 新增的 3 个用例精确变红
（26 pass / 3 fail），其余 26 个保持绿；恢复后 29/29 绿。证明测试确实钉住了该行为。

**存量测试锁定错误契约（本批第二次踩到，同 Derby）**：`sysqueries-completion.test.js` 原有一条
`it('MonetDB: escCols 用反引号')` —— 它**把错误行为写成了断言**，我修复后它变红（全量 2136 pass / **1 fail**）。
与 Derby 那条（锁定必然失败的 `GROUP_CONCAT` 查询形状）属同一模式：
**测试「通过」只说明代码符合当时的写法，不说明写法是对的。**
已改为断言双引号，并保留原文以便追溯。

> **顺带结论（未改，仅登记）**：ClickHouse 的 `escCols`（反引号）与 `quoteCol`（双引号）
> 也不一致，但 `quoteCol` 仅被 `buildStackPageSql` 使用，而 ClickHouse 在该函数里**已返回 null**
> ——即该不一致路径**不可达**（死路径）。按最小改动原则不动，此处留档备查。

---

## 五、本轮的方法论要点（可复用）

1. **同一条 SQL 在不同方言上合法性相反**：H2 接受 `SEPARATOR CHAR(30)`（实测产出 `a<RS>b`），
   HSQLDB 同一写法**语法错**。→ **绝不能按写法/参数个数类推方言合法性，必须逐库实测。**
2. **一个语法错会被下一个语法错掩盖**：修完 HSQLDB 的 SEPARATOR 后，才暴露出反引号问题
   （`required: AS`）。→ 修一处后**必须重投**，不能假设「一次修好」。
3. **引号判定散落多处 = 漏改**：`escCols`、`quoteCol`、`tableRef` 三处各自判定，只改一处仍会失败。
   → 改动引号策略时**必须全仓搜集判定点**（`grep -n "backtick\|反引号\|'\`'"`）。
4. **引擎报错文本是最强证据**：`CHAR required: a quoted string` 直接说明语法定义的限制，
   比任何文档推测都硬。

## 六、回归测试总账（`server/tests/sysQueries.concatArity.test.js`）

| 批次 | 内容 | 用例数 |
|---|---|---|
| 一（2026-09-20） | Oracle/DB2 CONCAT 参数超限 | 4 |
| 二（2026-09-20） | ClickHouse/Firebird 整行丢失 + 全方言 NULL 兜底 | 3 |
| 三（2026-09-20） | MySQL SCHEMA_QUERY 的 SEPARATOR | 4 |
| **四（本轮）** | **HSQLDB / H2 / Derby / 引号 / default 分支** | **11** |
| **五（本轮）** | **枚举 null 空查询不抛错 + 源码契约** | **3** |
| **六（本轮）** | **MonetDB 引号自洽（文档取证）** | **3** |
| 合计 | | **30** |

全量服务端：**2140 用例 / 2137 pass / 0 fail / 3 skip**（本轮累计新增 17 例，零回归）。
另：`dialectSqlBuilder.test.js`、`dumpRowSplit.sqlshape.test.js` 的形状契约保持不变、全绿。

> **注：`sysqueries-completion.test.js` 有 1 例被改写**（原锁定 MonetDB 反引号这一错误契约）——
> 非新增用例，故不计入上表「用例数」，但属本批必须记录的改动（详见「四·补2」）。
