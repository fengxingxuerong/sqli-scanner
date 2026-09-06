# P2-5b CLI no-op 参数落地：--union-cols / --no-cast / --union-from

> 日期：2026-09-05 · 批次：第 8 批 · 全量回归：**1346/1346 全绿**（基线 1338 + 新增 8）
> 项目：D:\projects\sqli-scanner（对标 sqlmap 的 Node 扫描引擎）

## 一、背景与审计结论（修正 07 文档）

07 文档将 7 个 CLI 参数列为"静默 no-op"待落地。本批先做逐参数真实接线审计，结论有修正：

| 参数 | 审计结论 | 处置 |
|---|---|---|
| `--flush-session` | **非 no-op**：scanRunner.js L102-119 已消费（freshQueries 强制全新扫描跳 session restore） | 从清单剔除 |
| `--no-cast` | 仅 sqlmapBridge 转发，原生提取零消费 | ✅ 本批落地 |
| `--union-cols` | UnionDetector/columnGuess 零消费 | ✅ 本批落地 |
| `--union-from` | 零消费 | ✅ 本批落地 |
| `--union-char` | 贯穿多处 MARKER 替换、改动大收益边际 | 放弃（保留接口注释） |
| `--no-escape` | escSql 是 SQL 安全转义，非 sqlmap 禁字符串转义绕 WAF 语义 | 放弃（避免为改而改） |
| `--hex` | 仅 sqlmapBridge 转发行 | 放弃（提取层已有 tamper hex 编码插件覆盖） |

## 二、落地改动（6 文件修改 + 1 新测试文件）

### 1. --union-cols（固定列数，跳过 ORDER BY 二分）

- `server/src/engine/columnGuess.js`：`binaryGuessColumns` 新增 `fixed` 选项——合法正整数时短路直接返回，零探测请求
- `server/src/engine/detectors/UnionDetector.js`：猜列处读 `ctx.config.unionCols` 传入 fixed
- `server/src/engine/Extractor.js`：`guessColumns(ctx)` 同样读 unionCols 传 fixed（枚举路径复用缓存）
- CLI 非法值（非数字/≤0/超上限）自动回退 ORDER BY 二分

### 2. --no-cast（数据提取禁用 CAST 显式转换）

- `server/src/engine/DialectSqlBuilder.js`：新增导出 `WRAP_NOCAST` 表——无 CAST 变体，各库用隐式文本化：
  - MySQL/TiDB 系：`CONCAT('__S__',(expr),'__E__')`（CONCAT 隐式转文本）
  - PostgreSQL/Oracle/DB2/HSQLDB 等：`('__S__' || (expr) || '__E__')`（|| 拼接隐式转）
  - Access：`&` 拼接
  - **SQL Server/Sybase：保守缺省**（`'a'+1` 会报错，调用方回退 WRAP 走 CAST）
- `Extractor.js` L141、`DBFingerprinter.js` L76 消费点按 `ctx.config?.noCast` 切换 WRAP_NOCAST / WRAP
- 语义：sqlmap --no-cast 是应对 WAF/应用层对 CAST() 关键字拦截的绕过手段（隐式类型转换达成同效果）

### 3. --union-from（强制伪表 FROM 子句）

- `server/src/engine/DialectSqlBuilder.js`：新增导出：
  - `sanitizeUnionFrom(v)`：清洗用户输入，仅保留 `[A-Za-z0-9_ .$()]`（剔除 `;`、`--`、`/*`、引号等，防注入逃逸）
  - `resolveFromClause(dbms, unionFrom)`：unionFrom 非空 → ` FROM <清洗值>`；否则完全走 fromDummy 方言自动判定
- 4 个消费点统一替换（injection.js discoverEchoColumnsDetailed、Extractor.js extractScalar + extractInline、DBFingerprinter.js）：
  - `fromDummy(dbms)` → `resolveFromClause(dbms, ctx?.config?.unionFrom)`
- ctx 可用性逐一确认：Extractor L1165 在 `extractInline(ctx, sql)` 作用域内 ✓

### 4. 帮助文档 & 测试

- `server/bin/cli.js` printHelp：新增 6 行参数说明（--union-cols/--union-from/--no-cast 标注"已接线"，--union-char/--no-escape/--hex 标注"保留接口"）
- 新测试 `server/tests/cliParams.noop.test.js`（8 用例）：
  1. unionCols=3 跳过 ORDER BY 二分（断言零 ORDER BY 请求 + columns=3）
  2. 非法 unionCols（'abc'）回退二分
  3. binaryGuessColumns fixed 选项零请求短路
  4. resolveFromClause/sanitizeUnionFrom 方言覆盖与清洗（含 SYSIBM.SYSDUMMY1 点号、(VALUES(0)) t 括号保留）
  5. unionFrom=dual 强制注入 MySQL 探测 payload
  6. WRAP_NOCAST 各库定义（MySQL CONCAT / PG·Oracle || / SQL Server 缺省回退）
  7. noCast=true extractScalar 无 CAST( 关键字、走 CONCAT 隐式拼接、值提取正确
  8. noCast 缺省仍走 CAST 显式转换（默认行为不变）

## 三、回归结果

- 全量：`node --env-file=.env.test --import=./tests/_setup.mjs --test --test-concurrency=3`
- **1346 tests / 35 suites / 1346 pass / 0 fail**（82.9s）
- 相关既有套件无回归：union-from-dual 4/4、extractor.test 等 23/23、columnGuess 6/6

## 四、工具链备注（本批新教训）

- 初次实现 WRAP_NOCAST 时第二个锚点（默认导出）miss → 脚本 exit(1) 前未写盘，WRAP_NOCAST 静默未落地；改用"全部锚点通过才写盘"模式后一次成功
- sanitizeUnionFrom 首版测试断言写错（把"被剔除的字符"当预期结果），实测清洗输出后修正——先探针验证再写断言
- Extractor.js import 行是 `fromDummy, WRAP, escSql, WRAP_NOCAST,` 多段式，需正则容忍

## 五、遗留

- P2-1 os-pwn / OLE Automation（GPL 授权约束）
- P2-2 DBMS 版本运行时分支（未系统化）
- P2-4 Digest/NTLM/客户端证书认证（下一批候选，历史倾向优先）
- P2-3 MongoDB 枚举器（NoSqlInjectionDetector 未被扫描路径消费）
- union-char/hex/no-escape 三参数保留接口、未实现（已文档标注）
