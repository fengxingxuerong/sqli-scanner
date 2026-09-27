// ============================================================================
// blackbox-lab / check-dbms-sig.mjs —— 定库签名「区分度」自检（P1-D 闭环版）
//
// 由来（P1 + A2 + P1-D 三个实例）：
//   · DB2 用常量串 'DB2' 当指纹 → 任何支持 UNION 的库都能执行 SELECT 'DB2' 并原样返回
//     → 前 9 个库没识别出来时必然命中 DB2（真 MySQL 被判 DB2）。【P1-C，已修】
//   · ClickHouse 与 SQLite 的 sig 都是「纯版本号」→ 互相误命中（真 MySQL 被判 ClickHouse）。
//   · [P1-D 2026-09-27 闭环] 旧版判据是「sig 层互斥」（某库的典型返回值只能命中自己的 sig），
//     它把**运行时不可达**的冲突也算了进去（H2VERSION()/sqlite_version() 这类专属探针，
//     别家引擎上根本执行不了 → 探针值不产生 → sig 写得再松也不会误判），导致 20 处
//     「永远修不完」的假缺陷。本版判据改为**运行时可达性模型**，与危害同源：
//
//     【判据（一条）】对每个库 X 的每个典型返回值 v（由 X 自己的探针产生），
//     按 DBFingerprinter 的真实遍历顺序（MariaDB 置首 + DB_VERSION 键序）模拟：
//     只对「探针在 X 上可执行」的条目做 sig 匹配，首个命中即定库 —— 判定必须恰好是 X。
//
//     模型依据的真实现（DBFingerprinter.js 版本回显通道）：逐库发**各自的**探针、
//     值喂**各自的** sig、首个命中立即返回；探针在目标上报错 = 无标记回显 = 跳过。
//     因此 sig 冲突只有在「双方探针在同一目标上都可执行」时才是真缺陷。
//
//   · 升级时模型抓到并修复的真实可达缺陷（payloads/index.js）：
//       ① ClickHouse 目标被判成 MySQL —— version() 在 CH 上可执行，MySQL 条目在前且
//          旧 sig 未锚定 `$`，吃下了 CH 的 4 段版本号。修：MySQL sig 锚定收尾。
//       ② TiDB 条目死代码 —— TiDB 的版本串先被 MySQL sig 吃下（无 TiDB 排除），
//          遍历永远轮不到 TiDB 自己。修：MySQL sig 负向排除 TiDB。
//       ③ Sybase 裸 /ASE/i 命中 "Datab**ase**"（L46 同款子串病，Oracle/DM8/Access
//          的 banner 全中招）。修：\bASE\b 词边界。
//
//   [口径边界] 本脚本只模型 **版本回显通道**（DB_VERSION sig 层）；报错签名与时间向量
//   定库是另外两条通道，各有自己的签名表与顺序，运行时可达性要靠真引擎测
//   （multi-engine-lab / real-*-lab 的 SQLI_UNION_DEBUG A/B）。
//
// 用法：node e2e/blackbox-lab/check-dbms-sig.mjs
// ============================================================================

import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '../..');
// Windows 下 import() 不接受裸绝对路径（ERR_UNSUPPORTED_ESM_URL_SCHEME），须转 file:// URL
const { DB_VERSION } = await import(
  pathToFileURL(path.join(ROOT, 'server/src/engine/payloads/index.js')).href
);

// 各库「典型返回值」样本。来源标注：
//   [实测] 本机/项目 e2e 真引擎见过  [文档] 官方文档格式  [推断] 按产品命名规则推的，待真机确认
const SAMPLES = {
  MySQL: [['8.0.28', '实测'], ['5.7.42-log', '文档']],
  MariaDB: [['10.11.6-MariaDB', '实测'], ['11.4.13-MariaDB-log', '实测']],
  PostgreSQL: [['PostgreSQL 16.2 on x86_64-pc-linux-gnu, compiled by gcc', '实测'], ['PostgreSQL 18.3', '实测']],
  'SQL Server': [['Microsoft SQL Server 2019 (RTM-CU18)'], ['SQL Server 2017'], ['Microsoft SQL Azure']],
  SQLite: [['3.45.1', '实测'], ['3.39.4']],
  Oracle: [['Oracle Database 19c Enterprise Edition Release 19.0.0.0.0 - Production'], ['Oracle Database 12c']],
  TiDB: [['5.7.25-TiDB-v7.5.0', '实测']],
  DM8: [['DM Database Server Version 8.1.3.140'], ['DM8']],
  ClickHouse: [['23.8.1.1', '文档'], ['24.3.2.23']],
  // DB2 的真实 version 语义：DB2 无标量 version()，常用 CURRENT SERVER / SERVICE_LEVEL
  DB2: [['DB2/LINUXX8664 11.5.8', '文档'], ['DB2 v11.5.8.0'], ['SQL11058']],
  Sybase: [['Adaptive Server Enterprise 16.0.0'], ['Sybase ASE 15.7']],
  Firebird: [['3.0.7.33374', '文档'], ['2.5.9']],
  Informix: [['IBM Informix Dynamic Server Version 14.10.FC9'], ['Informix Server 12.10']],
  // [EXCL-FIX 2026-09-19] 样本换成**真引擎回显值**：H2 现在探测的是独有的 H2VERSION()，
  // 实测（multi-engine-lab JDBC）回显 `2.2.224`；旧样本是 version() 的带日期形式，已不再是被探测的值。
  H2: [['2.2.224', '实测 H2VERSION() 回显'], ['1.4.200', '文档/推断']],
  Access: [['Microsoft Access 2016'], ['Microsoft Office Access 2007'], ['Microsoft Access Database Engine']],
  // [P1-D 2026-09-27] 样本必须是**探针真实回显值**（判据与危害同源，EXCL-FIX 2026-09-20 同理）：
  // HSQLDB/Derby 的拼接探针回显的是 "HSQLDB 103" / "DERBY 24"（multi-engine-lab 真 JDBC 实测），
  // 不是 version() 形态的 banner。
  HSQLDB: [['HSQLDB 103', '实测：探针回显'], ['HSQLDB 2.5.0', '文档（sig 同样覆盖）']],
  Derby: [['DERBY 24', '实测：探针回显'], ['Apache Derby 10.15.2.0', '文档（sig 同样覆盖）']],
  MonetDB: [['11.47.11', '文档']],
};

// 版本回显通道「按设计不自证」的条目（P1-C 教训的落地形态）：
// 探针是常量串 → 任何库都能原样回显 → sig 必须**拒绝**这个常量（否则就是 DB2 误判事故的重演）。
// 因此这三家的版本通道**不可能**自己定回自己，属有意设计而非缺陷——定库由报错签名
//（DB2 SQL Error / Informix / Access 的 ODBC/Jet 特征）与专属伪表承担。模型跳过并显式说明。
const VERSION_CHANNEL_EXEMPT = new Set(['DB2', 'Informix', 'Access']);

// ── 运行时可达性模型 ─────────────────────────────────────────────────────────
// 探针「在哪些目标引擎上可执行」。依据：
//   · version()：MySQL 系标准函数，ClickHouse 亦原生支持（P1-D 抓到的误判通道即此）；
//   · @@version：MySQL 系、SQL Server、Sybase（ASE）；
//   · v$version banner：Oracle 与其兼容分支 DM8（DM8 条目因此存在）；
//   · 其余条目 = 专属函数/专属 FROM（H2VERSION / sqlite_version / rdb$get_context /
//     sys.version 视图 / HSQLDB·Derby 的系统表 FROM / 常量串已被 sig 拒收）——
//     别家执行即报错，探针值不产生，sig 写得再松也不可达。
const SHARED_PROBES = {
  'version()': ['MariaDB', 'MySQL', 'PostgreSQL', 'TiDB', 'ClickHouse'],
  '@@version': ['MariaDB', 'MySQL', 'PostgreSQL', 'TiDB', 'SQL Server', 'Sybase'],
  '(SELECT banner FROM v$version WHERE rownum=1)': ['Oracle', 'DM8'],
};
const reachableOn = (target, dbms, func) => (SHARED_PROBES[String(func)] ?? [dbms]).includes(target);

// 与 DBFingerprinter.js 版本回显通道完全一致的遍历顺序（MariaDB 置首）
const order = ['MariaDB', ...Object.keys(DB_VERSION).filter((k) => k !== 'MariaDB')];

console.log('=== 定库签名区分度自检（P1-D 闭环版：运行时可达性模型） ===');
console.log('判据：X 库的典型返回值，按真实遍历序模拟「首个 sig 命中即定库」，必须恰好定回 X\n');

const violations = [];
const sigLayerConflicts = [];

for (const [target, samples] of Object.entries(SAMPLES)) {
  if (VERSION_CHANNEL_EXEMPT.has(target)) {
    console.log(`  [豁免] ${target}：版本探针是常量串（按设计 sig 拒收裸常量），定库由报错签名承担 —— 不进模型`);
    continue;
  }
  for (const [sample, src] of samples) {
    let verdict = null;
    const tried = [];
    for (const dbms of order) {
      const info = DB_VERSION[dbms];
      if (!reachableOn(target, dbms, info.func)) continue; // 探针在 target 上跑不动 → 无回显 → 跳过
      tried.push(dbms);
      if (info.sig.test(sample)) { verdict = dbms; break; }
    }
    if (verdict !== target) {
      violations.push({ target, sample, verdict, tried, src: src || '' });
      console.log(`  [误判] 目标=${target.padEnd(11)} 样本=${JSON.stringify(sample)}`);
      console.log(`          判成了：${verdict ?? '定库失败(null)'}（尝试链：${tried.join(' → ')}）`);
    }
  }
}

// ── sig 层互撞参考表（仅信息展示，不影响退出码）──────────────────────────────
// 保留旧判据的输出供参考：下面这些「sig 互撞」里，凡涉及专属探针的都在运行时不可达
//（升级前它制造了 20 处假缺陷计数）；若某一行同时出现在上方 [误判] 里才是真缺陷。
const sigs = Object.entries(DB_VERSION).map(([dbms, v]) => [dbms, v.sig]);
for (const [dbms, samples] of Object.entries(SAMPLES)) {
  for (const [sample] of samples) {
    const hits = sigs.filter(([, sig]) => sig.test(sample)).map(([d]) => d);
    const others = hits.filter((d) => d !== dbms);
    if (others.length) sigLayerConflicts.push({ dbms, sample, others });
  }
}
if (sigLayerConflicts.length) {
  console.log('\n=== sig 层互撞（参考，运行时大多不可达，不进退出码）===');
  for (const c of sigLayerConflicts) {
    console.log('  [sig互撞] %s %j ← 也被 %s 命中', c.dbms, c.sample, c.others.join(', '));
  }
}

// 常量串 / 通用函数的跨库可执行性检查（高危区说明，不影响退出码）
console.log('\n=== func 跨库可执行性（区分度只能由 sig 承担的条目）===');
const UNIVERSAL = /^\s*(?:'(?:[^']*)'|"(?:[^"]*)"\s*)$/; // 纯字面量
const COMMON_FN = /^\s*(?:version\(\)|@@version|sqlite_version\(\))\s*$/i;
for (const [dbms, v] of Object.entries(DB_VERSION)) {
  const f = String(v.func || '');
  if (UNIVERSAL.test(f)) {
    console.log('  [无区分度] %s func=%s  → 常量字面量任何库都能原样返回，sig 必须能拒绝「裸常量」', dbms, f);
  } else if (COMMON_FN.test(f)) {
    console.log('  [通用函数] %s func=%s  → 可执行面见 SHARED_PROBES，靠 sig/顺序区分', dbms, f);
  }
}

console.log('\n=== 汇总 ===');
console.log('  运行时可达误判（模型判定）: %d 处', violations.length);
console.log('  sig 层互撞（参考）        : %d 处', sigLayerConflicts.length);
if (violations.length) {
  const byTarget = new Map();
  for (const v of violations) byTarget.set(v.target, (byTarget.get(v.target) ?? 0) + 1);
  console.log('\n  误判明细（按目标聚合）:');
  for (const [t, n] of byTarget) console.log('    %s: %d 个样本被定成别家', t, n);
}
process.exit(violations.length ? 1 : 0);
