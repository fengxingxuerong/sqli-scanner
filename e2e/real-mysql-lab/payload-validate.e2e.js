// ============================================================================
// e2e/real-mysql-lab/payload-validate.e2e.js —— payload 合法性回归防线
//
// 背景：mock 靶场用正则匹配响应，无法发现 SQL 语法非法的 payload 模板
// （此前 MySQL 堆叠模板裸 SLEEP(n) 在真实 MySQL 报 1064 语法错误，mock 全过掩盖缺陷）。
//
// 校验方法：模板设计为注入到「已有查询上下文」（boundary 系统），裸执行必然语法错误。
// 因此模拟两种真实注入上下文包裹填充后的模板：
//   · 数值上下文：SELECT id FROM users WHERE id = {FILLED}
//   · 字符串上下文：SELECT id FROM users WHERE username = '{FILLED}'
// 模板在任一上下文无 1064（ER_PARSE_ERROR）即判合法；两种均 1064 才判失败。
// 语义类错误（表/列不存在 1146/1054 等）允许并单列统计（不判失败）。
//
// 运行：node e2e/real-mysql-lab/payload-validate.e2e.js
// 环境变量：MYSQL_PORT=3307（3306 被 WorkBuddy 实例占用）；无 MySQL 实例时 exit 2（CI 跳过）
// ============================================================================
import { createRequire } from 'node:module';
const _require = createRequire(new URL('../../server/package.json', import.meta.url));
const mysql = _require('mysql2/promise');

const { PAYLOADS: P, fillPayload: fill } = await import(
  'file:///D:/projects/sqli-scanner/server/src/engine/payloads.js'
);

const CONF = {
  host: process.env.MYSQL_HOST || '127.0.0.1',
  port: Number(process.env.MYSQL_PORT) || 3307,
  user: process.env.MYSQL_USER || 'root',
  password: process.env.MYSQL_PASSWORD || 'root',
  database: process.env.MYSQL_DATABASE || 'sqli_lab',
  multipleStatements: true, // stacked 模板需要
  connectTimeout: 5000,
};

// 探测数据库可用性：不可用 exit 2（CI 跳过而非失败）
let conn;
try {
  conn = await mysql.createConnection(CONF);
  await conn.query('SELECT 1');
} catch (e) {
  console.error(`[skip] MySQL 不可达（${e.code || e.message}）——payload 合法性校验跳过`);
  process.exit(2);
}

const isSyntaxError = (e) => e?.code === 'ER_PARSE_ERROR' || e?.errno === 1064;
// fillPayload 占位符大小写兼容兜底
const safeFill = (tpl) => {
  try {
    const out = fill(tpl, { orig: '1', sleep: '0', num: '7', sep: '-- -' });
    if (typeof out === 'string' && !out.includes('{')) return out;
  } catch { /* 走兜底 */ }
  return tpl
    .replaceAll('{ORIG}', '1').replaceAll('{SLEEP}', '0')
    .replaceAll('{NUM}', '7').replaceAll('{SEP}', '-- -');
};

// 真实注入上下文（对应 boundary 系统的典型闭合形态）：
// 模板在任一上下文中语法合法（无 1064）即通过；语义错误=语法已被接受，同样合法。
//   numeric       : WHERE id = 1' AND ...          （裸拼接族）
//   string-noclose: WHERE username = '1' AND ...   （模板自带注释终结符，不补尾引号）
//   string-close  : WHERE username = '1' AND ...'  （模板以行注释结尾，尾引号被注释）
//   paren-string  : WHERE id = ('1')) AND ...      （括号包裹族，模板含 )) 闭合）
const contexts = [
  ['numeric', (f) => `SELECT id FROM users WHERE id = ${f}`],
  ['string-noclose', (f) => `SELECT id FROM users WHERE username = '${f}`],
  ['string-close', (f) => `SELECT id FROM users WHERE username = '${f}'`],
  ['paren-string', (f) => `SELECT id FROM users WHERE id = ('${f}`],
  // 双括号/双引号闭合族（覆盖 `'))`、`")`、`"))` 等模板前缀）
  ['paren2-string', (f) => `SELECT id FROM users WHERE id = (('${f}`],
  ['paren-dquote', (f) => `SELECT id FROM users WHERE id = ("${f}`],
  ['paren2-dquote', (f) => `SELECT id FROM users WHERE id = (("${f}`],
];

// 遍历默认池：MariaDB/TiDB 由 index.js 深拷贝 MySQL 继承，只测 MySQL 源
const techniques = ['union', 'error', 'boolean', 'time', 'stacked', 'inline'];
let total = 0, syntaxFail = 0, semantic = 0, ok = 0;
const failures = [];
const semanticSamples = new Map();

for (const tech of techniques) {
  const tpls = P.MySQL?.[tech] || [];
  for (let i = 0; i < tpls.length; i++) {
    const filled = safeFill(tpls[i]);
    total++;
    let hadSemantic = false;
    let isParseError = true;
    const firstParseErr = { msg: '', sql: '' };
    for (const [ctxName, wrap] of contexts) {
      try {
        await conn.query(wrap(filled));
        isParseError = false; // 任一上下文合法即通过
        break;
      } catch (e) {
        if (isSyntaxError(e)) {
          if (!firstParseErr.msg) firstParseErr.msg = String(e.message).slice(0, 160);
          if (!firstParseErr.sql) firstParseErr.sql = `${ctxName}: ${wrap(filled).slice(0, 140)}`;
          continue; // 该上下文语法错误，试下一个
        }
        // 语义错误 = 语法已被解析器接受 → 模板合法
        hadSemantic = true;
        isParseError = false;
        break;
      }
    }
    if (isParseError) {
      syntaxFail++;
      failures.push({ tech, idx: i, tpl: tpls[i], ...firstParseErr });
    } else if (hadSemantic) {
      semantic++;
    } else {
      ok++;
    }
  }
}

console.log(`\n===== MySQL payload 合法性校验（双上下文包裹） =====`);
console.log(`总计 ${total} 条模板 | 语法合法执行 ${ok} | 语义类错误（允许）${semantic} | 语法错误（失败）${syntaxFail}`);
if (semanticSamples.size) {
  console.log('语义错误分布:', JSON.stringify([...semanticSamples.entries()]));
}
if (failures.length) {
  console.log('\n语法错误明细（两种上下文均 1064）:');
  failures.forEach((f) => console.log(`  [${f.tech}#${f.idx}] ${f.msg}\n    tpl: ${f.tpl}\n    ${f.sql}`));
}
await conn.end();
process.exit(syntaxFail > 0 ? 1 : 0);
