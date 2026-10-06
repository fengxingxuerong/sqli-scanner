// ============================================================================
// e2e/real-mysql-lab/versionedForms.e2e.mjs —— 版本门条目的「真库可执行 + 真假差分」验证
//
// 为什么要单独一支：注册表条目声称"这条只在 MySQL 8.0.14+ 投放"是不够的，还得证明
//   ① 它在真 MySQL 上**不是语法错误**（mock 靶场用正则匹配响应，发现不了非法 SQL ——
//      这条教训来自同目录 payload-validate.e2e.js：裸 SLEEP(n) 在真库报 1064 而 mock 全过）；
//   ② 它有**真假差分**（布尔通道靠的就是"真时留行、假时不留行"；只有语法没有差分 = 废向量）。
//
// 与执行同源：已入库条目不是"照抄一份 SQL 来测"，而是从注册表取出条目、用引擎自己的
//   fillPayload 渲染 —— 测的就是发出去的那串。候选区（尚未入库）允许失败，不影响退出码。
//
// 运行（必须走沙箱；宿主 3306 通常没有实例）：
//   python e2e/run-with-sandbox.py e2e/real-mysql-lab/versionedForms.e2e.mjs
// 退出码：0 已入库条目全部通过 / 1 有失败 / 2 连不上 MySQL（SKIP 口径，与 payload-validate 一致）
// ============================================================================
import { createRequire } from 'node:module';
const _require = createRequire(new URL('../../server/package.json', import.meta.url));
const mysql = _require('mysql2/promise');

const { PAYLOAD_REGISTRY } = await import('../../server/src/engine/payloadRegistry.js');
const { fillPayload } = await import('../../server/src/engine/payloads/index.js');

const CONF = {
  host: process.env.MYSQL_HOST || '127.0.0.1',
  port: Number(process.env.MYSQL_PORT) || 3307,
  user: process.env.MYSQL_USER || 'root',
  password: process.env.MYSQL_PASSWORD ?? 'root',
  connectTimeout: 6000,
};

/** 自包含数值上下文：不依赖靶场 schema，只依赖"数值上下文 + WHERE"这个形态本身 */
const numericCtx = (payload) => `SELECT t.id FROM (SELECT 1 AS id) t WHERE t.id = ${payload}`;

/** 已入库的版本门条目（id 前缀即契约：payloadVersion.patch.test.js ④⑤ 用同一批 id） */
const SHIPPED = PAYLOAD_REGISTRY.filter((e) => e.id.startsWith('mysql-bool-') && e.minVersion && typeof e.minVersion === 'object' && e.minVersion.patch != null);

/**
 * 候选区：还没进注册表，先拿真库差分说话（失败不判红，但也不许进条目）。
 * 留在这里的两条都是**踩过/会踩**的形态：
 *   · 窗口里写 `ORDER BY 1` ⇒ 真库报 ER_WINDOW_ILLEGAL_ORDER_BY（裸数字被当列序号）；
 *   · 把已入库条目扩到引号上下文（boundary "'"）—— 模板不为引号上下文设计过，
 *     在这里过了才允许改条目的 boundary，而不是"顺手多声明一个边界"。
 */
const CANDIDATES = [
  {
    id: 'candidate-window-ordinal-trap',
    note: '窗口 ORDER BY 裸数字（预期报错，用来钉住这个坑）',
    trueSQL: `SELECT t.id FROM (SELECT 1 AS id) t WHERE t.id = 1 AND (SELECT ROW_NUMBER() OVER (ORDER BY 1))=1`,
    expect: 'error',
  },
];

let conn;
try {
  conn = await mysql.createConnection(CONF);
} catch (e) {
  console.log(`[versionedForms] SKIP：连不上 MySQL（${e.code || e.message} @ ${CONF.host}:${CONF.port}）`);
  console.log('[versionedForms] 正确跑法：python e2e/run-with-sandbox.py e2e/real-mysql-lab/versionedForms.e2e.mjs');
  process.exit(2);
}

const [vrow] = await conn.query('SELECT VERSION() AS v');
console.log(`[versionedForms] 真 MySQL VERSION() = ${vrow[0].v} @ ${CONF.host}:${CONF.port}`);

async function probe(sql) {
  try {
    const [rows] = await conn.query(sql);
    return { rows: rows.length };
  } catch (e) {
    return { error: `${e.code || ''} ${String(e.sqlMessage || e.message).slice(0, 100)}` };
  }
}

console.log('\n—— 已入库条目（注册表 + fillPayload 渲染，判退出码）——');
let shippedFail = 0;
for (const e of SHIPPED) {
  const t = numericCtx(fillPayload(e.template, { orig: '1' }));
  const f = numericCtx(fillPayload(e.falseTemplate, { orig: '1' }));
  const rt = await probe(t);
  const rf = await probe(f);
  const ok = rt.rows === 1 && rf.rows === 0;
  if (!ok) shippedFail++;
  console.log(`  ${e.id.padEnd(26)} min=${JSON.stringify(e.minVersion)} 真=${rt.rows ?? rt.error} 假=${rf.rows ?? rf.error} ${ok ? 'PASS' : 'FAIL'}`);
  if (!ok && rt.error) console.log(`      真分支 SQL：${t.slice(0, 160)}`);
}
console.log(`  小计：${SHIPPED.length - shippedFail}/${SHIPPED.length} 通过`);

console.log('\n—— 候选/扩面探测（尚未入库，失败不判红）——');
for (const c of CANDIDATES) {
  const r = await probe(c.trueSQL);
  const got = r.error ? 'error' : `${r.rows} 行`;
  console.log(`  ${c.id.padEnd(34)} ${got}  期望=${c.expect}  ${got === c.expect ? '符合预期' : '与预期不符'}（${c.note}）`);
}
// 引号上下文能不能扩：条目当前只声明数值边界，这里探"如果扩会怎样"
const stringCtx = (payload) => `SELECT t.u FROM (SELECT 'abc' AS u) t WHERE t.u = 'abc${payload}'`;
for (const e of SHIPPED) {
  const r = await probe(stringCtx(fillPayload(e.template, { orig: '' })));
  const f = await probe(stringCtx(fillPayload(e.falseTemplate, { orig: '' })));
  const ok = !r.error && r.rows === 1 && f.rows === 0;
  console.log(`  ${e.id.padEnd(34)} 引号上下文：真=${r.rows ?? String(r.error).slice(0, 42)} 假=${f.rows ?? String(f.error).slice(0, 30)} ${ok ? '可议扩边界' : '不可扩（保持只声明数值边界）'}`);
}

await conn.end();

if (SHIPPED.length === 0) {
  console.log('\n❌ 注册表里一条版本门条目都没取到 —— 采集面空了，本文件就是在防这种情况');
  process.exit(1);
}
if (shippedFail) {
  console.log(`\n❌ ${shippedFail} 条已入库条目在真库上没有差分 ⇒ 回滚条目或修模板`);
  process.exit(1);
}
console.log('\n✅ 已入库版本门条目全部在真 MySQL 上有真假差分');
