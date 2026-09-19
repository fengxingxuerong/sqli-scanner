// ============================================================================
// blackbox-lab / check-dbms-sig.mjs —— 定库签名「区分度」自检
//
// 由来（P1 + A2 两个实例）：
//   · DB2 用常量串 'DB2' 当指纹 → 任何支持 UNION 的库都能执行 SELECT 'DB2' 并原样返回
//     → 前 9 个库没识别出来时必然命中 DB2（真 MySQL 被判 DB2）。
//   · ClickHouse 与 SQLite 的 sig 都是「纯版本号」→ 互相误命中（真 MySQL 被判 ClickHouse）。
//
// 判据（一条）：**某个库的典型返回值，只能命中它自己的 sig**。
// 命中 ≥2 个 → 冲突；命中 0 个 → 该库定不回来（漏检）。
//
// [口径边界 2026-09-19] 本脚本只看 **sig 层**，不看运行时遍历：真实定库是「按 DB_VERSION 顺序
// 逐条发 exclusive/common 探针，谁先命中自己 sig 谁赢」。因此这里的冲突数**不等于**运行时误判数
// —— 例如 H2 改用 H2VERSION() 后，裸版本号 sig 与 MySQL/Firebird/MonetDB 的重叠在运行时已不可达
// （那些库的探针在 H2 上报错、无标记回显）。运行时可达性要靠真引擎测（见 multi-engine-lab
// 的 SQLI_UNION_DEBUG A/B），别拿本脚本的 20 处冲突当"线上会错 20 次"。
//
// 另外单独检查「func 是否跨库可执行」：常量串与通用函数在任何库上都能返回内容，
// 区分度**只能**由 sig 承担 —— 这类条目是 sig 缺陷的高危区。
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
  HSQLDB: [['2.7.2 (2023-06-28)', '项目 e2e 真 JDBC'], ['HSQLDB 2.5.0']],
  Derby: [['10.16.1.1 - (1873585)', '项目 e2e 真 JDBC'], ['Apache Derby 10.15.2.0']],
  MonetDB: [['11.47.11', '文档']],
};

const sigs = Object.entries(DB_VERSION).map(([dbms, v]) => [dbms, v.sig]);

console.log('=== 定库签名区分度自检 ===');
console.log('判据：某库的典型返回值，只能命中它自己的 sig\n');

const conflicts = [];
const misses = [];

for (const [dbms, samples] of Object.entries(SAMPLES)) {
  for (const [sample, src] of samples) {
    const hits = sigs.filter(([, sig]) => sig.test(sample)).map(([d]) => d);
    const self = hits.includes(dbms);
    const others = hits.filter((d) => d !== dbms);
    if (others.length) {
      conflicts.push({ dbms, sample, hits, others, src: src || '' });
      console.log('  [冲突] %s %j', dbms, sample);
      console.log('           命中 %d 个: %s   ← 会误判为 %s', hits.length, hits.join(', '), others.join(', '));
    } else if (!self) {
      misses.push({ dbms, sample });
      console.log('  [漏] %s %j → 自己的 sig 都没命中（该库定不回来）', dbms, sample);
    }
  }
}

// 常量串 / 通用函数的跨库可执行性检查
console.log('\n=== func 跨库可执行性（区分度只能由 sig 承担）===');
const UNIVERSAL = /^\s*(?:'(?:[^']*)'|"(?:[^"]*)"\s*)$/; // 纯字面量
const COMMON_FN = /^\s*(?:version\(\)|@@version|sqlite_version\(\))\s*$/i;
for (const [dbms, v] of Object.entries(DB_VERSION)) {
  const f = String(v.func || '');
  if (UNIVERSAL.test(f)) {
    console.log('  [无区分度] %s func=%s', dbms, f);
    console.log('             常量字面量：任何支持 UNION 的库都能原样返回它 → sig 必须能拒绝「裸常量」');
  } else if (COMMON_FN.test(f)) {
    console.log('  [通用函数] %s func=%s  → 多库都能执行，返回各自版本，靠 sig 区分', dbms, f);
  }
}

console.log('\n=== 汇总 ===');
console.log('  sig 冲突（同一返回值命中多个库）: %d 处', conflicts.length);
console.log('  sig 漏检（自己的值都命不中）: %d 处', misses.length);
const badSig = Object.entries(DB_VERSION).filter(([, v]) => !(v.sig instanceof RegExp)).map(([d]) => d);
if (badSig.length) console.log('  sig 类型异常: %s', badSig.join(','));

if (conflicts.length) {
  console.log('\n  冲突明细（按库聚合）:');
  const byDbms = new Map();
  for (const c of conflicts) {
    if (!byDbms.has(c.dbms)) byDbms.set(c.dbms, new Set());
    for (const o of c.others) byDbms.get(c.dbms).add(o);
  }
  for (const [d, others] of byDbms) console.log('    %s ⟷ %s', d, [...others].join(', '));
}
process.exit(conflicts.length || misses.length ? 1 : 0);
