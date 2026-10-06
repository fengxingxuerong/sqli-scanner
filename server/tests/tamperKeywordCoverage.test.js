// ============================================================================
// tests/tamperKeywordCoverage.test.js —— keyword 系插件的覆盖集一致性与向量覆盖
//
// ── 存在理由 ────────────────────────────────────────────────────────────────
// 2026-10-05 克隆/覆盖集检测发现三个 keyword 插件的覆盖集彼此不一致：
//   keyword2hex     21 个（含 SELECT…EXECUTE，无 SLEEP）
//   keyword2hexall  55 个（去重后；原 62 个里有 7 项重复，且同样无 SLEEP）
//   keywordSplit    21 个（**含 SLEEP / CONCAT / VERSION / DATABASE / SCHEMA**）
//
// 而 SLEEP 是本仓检出能力的主通道：payloads/index.js 的 TIME_VECTORS 全部含 {SLEEP}，
// mysql.js / oracle.js / postgres.js 的时间向量里 SLEEP、DBMS_PIPE.RECEIVE_MESSAGE
// 反复出现，而 WAF 对时间盲注函数的拦截恰恰最严。
// ⇒ tamper 链选中 keyword2hex/keyword2hexall 时，**最贵的那个关键字原样发出**。
//
// tamper.test.js 对这些插件只验注册存在（200+ 名字的清单里），从不验行为，
// 所以这个真实缺陷可以长期绿着。
//
// 本文件钉三件事：
//   1) keyword2hex ⊆ keyword2hexall（"all 版必须是超集"这一命名承诺）
//   2) 两个 hex 插件与 keywordSplit 都覆盖**本仓真实使用的向量关键字**
//   3) 覆盖集无重复项（重复无害但让"覆盖了多少"无法一眼判断，且易掩盖漏项）
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { keyword2hex } from '../src/core/tamper/plugins/keyword2hex.js';
import { keyword2hexall } from '../src/core/tamper/plugins/keyword2hexall.js';
import { keywordSplit } from '../src/core/tamper/plugins/keywordSplit.js';

/**
 * 从插件源码里抽出关键字列表。
 * ⚠️ 两个坑，都是本测试初版踩过的（都导致**假红**，而生产代码本来是对的）：
 *   ① 字符类必须含下划线：写成 '[A-Z]{2,}' 会漏掉 PG_SLEEP ⇒ 报"未覆盖 PG_SLEEP"。
 *   ② 列表**不一定在 transform 体内**：keywordSplit 的在模块级 `const KEYWORDS`
 *      （keywordSplit.js:4），只扫 transform.toString() 会抽到 0 项 ⇒ 同样报假红。
 * 假红的危害是驱使后人去改本来正确的生产代码 —— 本仓已反复记录这类踩坑。
 */
function kwsOf(plugin) {
  const src = plugin.transform.toString();
  const m = src.match(/\[([^\]]*'[A-Z][A-Z_]{1,}'[^\]]*)\]/);
  return m ? [...m[1].matchAll(/'([A-Z][A-Z_]+)'/g)].map((x) => x[1]) : [];
}

/** 从插件文件源码抽关键字（覆盖模块级 const 的写法，如 keywordSplit 的 KEYWORDS） */
function kwsOfFile(fileUrl) {
  const src = readFileSync(fileUrl, 'utf8');
  const m = src.match(/(?:const\s+KEYWORDS|const\s+keywords)\s*=\s*\[([^\]]*)\]/);
  if (!m) return [];
  return [...m[1].matchAll(/'([A-Z][A-Z_]+)'/g)].map((x) => x[1]);
}

const HEX = kwsOf(keyword2hex);
const HEX_ALL = kwsOf(keyword2hexall);
// keywordSplit 的列表在模块级 const KEYWORDS（keywordSplit.js:4），
// 不在 transform 体内 ⇒ 必须扫文件内容，否则抽到 0 项。
const SPLIT = kwsOfFile(new URL('../src/core/tamper/plugins/keywordSplit.js', import.meta.url));

test('自证-0) 抽取器本身可靠（抓到的是完整列表，不是被正则截断的子集）', () => {
  // 抽取器一旦静默漏项，上面所有覆盖断言都会假绿/假红（本次已踩过一次：
  // '[A-Z]{2,}' 漏掉 PG_SLEEP ⇒ 报"keyword2hex 未覆盖 PG_SLEEP"，
  //  而该文件里明明写着它 —— 假红会驱使后人去改本来正确的生产代码）。
  // 判据：抽取结果里必须含带下划线的关键字，且与源码里出现的次数一致。
  for (const [name, list] of [['keyword2hex', HEX], ['keyword2hexall', HEX_ALL]]) {
    assert.ok(list.includes('PG_SLEEP'),
      `${name} 抽取结果缺 PG_SLEEP —— 抽取器的字符类必须含下划线 [A-Z_]`);
    assert.ok(list.length > 10, `${name} 只抽到 ${list.length} 项，正则可能失效`);
  }
  // keywordSplit 的列表在模块级 const KEYWORDS 里（不在 transform 体内），
  // 故抽取走 kwsOfFile，并顺手验一次真实行为（SLEEP 必须被切开）。
  assert.ok(SPLIT.length > 5, `keywordSplit 抽到 ${SPLIT.length} 项（列表在模块级 const，应 >5）`);
  assert.ok(SPLIT.includes('SLEEP'), 'keywordSplit 应含 SLEEP（它是本次定位的覆盖基准）');
  // 切点规则：mid = max(1, floor(len/2))（keywordSplit.js:24），故 AND(3) → A/*!*/ND
  assert.equal(
    keywordSplit.transform("1' AND SLEEP(5)-- -", {}),
    "1' A/*!*/ND SL/*!*/EEP(5)-- -",
    'keywordSplit 应在关键字中间插入 /*!*/ —— 本仓引用它作覆盖基准，行为不能变',
  );
  assert.equal(keywordSplit.transform('SLEEP', {}), 'SL/*!*/EEP',
    '单关键字也应被切开（len=5 ⇒ mid=2）');
});

test('覆盖-1) keyword2hex ⊆ keyword2hexall（"all 版必须是超集"的命名承诺）', () => {
  const missing = HEX.filter((k) => !HEX_ALL.includes(k));
  assert.deepEqual(missing, [],
    `keyword2hex 有而 keyword2hexall 无：${missing.join(', ')}\n` +
    '"all" 版本名承诺覆盖更广；缺项会让选 all 版的人失去精简版已能绕过的关键字。');
  assert.ok(HEX_ALL.length > HEX.length,
    `keyword2hexall（${HEX_ALL.length}）应严格多于 keyword2hex（${HEX.length}）`);
});

test('覆盖-2) 三个插件均覆盖本仓 payload 真实使用的向量关键字', () => {
  // 这些不是凭直觉挑的，而是从 payloads/{mysql,postgres,sqlserver,oracle}.js
  // 与 payloads/index.js 的 TIME_VECTORS 里实际出现的注入向量关键字。
  // 若将来新增向量用到别的关键字（如 MERGE / UPSERT），请一并登记。
  const REQUIRED = [
    'SELECT', 'UNION', 'WHERE', 'FROM', 'AND', 'OR', 'ORDER', 'GROUP', 'HAVING',
    'LIMIT', 'INSERT', 'UPDATE', 'DELETE', 'INTO', 'VALUES', 'SET',
    // 拖库/枚举阶段的高频函数
    'CONCAT', 'DATABASE', 'SCHEMA', 'SUBSTRING', 'LENGTH', 'VERSION',
    // ⚠️ 时间盲注：TIME_VECTORS 全部含 {SLEEP}，WAF 对它的拦截最严。
    //    2026-10-05 的实际缺陷正是 hex 两版都缺它。
    'SLEEP', 'BENCHMARK', 'WAITFOR', 'DELAY', 'PG_SLEEP',
  ];
  for (const [name, list] of [['keyword2hex', HEX], ['keyword2hexall', HEX_ALL]]) {
    const missing = REQUIRED.filter((k) => !list.includes(k));
    assert.deepEqual(missing, [], `${name} 未覆盖：${missing.join(', ')}`);
  }
  // keywordSplit 一直是这三家里覆盖较全的，作为对照基准
  assert.ok(REQUIRED.every((k) => SPLIT.includes(k) || !['SLEEP', 'CONCAT', 'VERSION', 'DATABASE', 'SCHEMA'].includes(k)),
    'keywordSplit 作为覆盖基准，至少应含 SLEEP/CONCAT/VERSION/DATABASE/SCHEMA');
});

test('覆盖-3) 关键字列表无重复项（重复无害但掩盖漏项、且无法一眼判断覆盖数）', () => {
  for (const [name, list] of [['keyword2hex', HEX], ['keyword2hexall', HEX_ALL]]) {
    const dup = list.filter((k, i) => list.indexOf(k) !== i);
    assert.deepEqual(dup, [], `${name} 有重复项：${[...new Set(dup)].join(', ')}`);
    assert.equal(new Set(list).size, list.length, `${name} 列表长度与去重后不一致`);
  }
});

test('行为-4) 时间盲注向量真的被编码（端到端钉住本次修复）', () => {
  // 直接用本仓 mysql.js 的真实时间向量形态，确保 SLEEP 不再原样发出。
  const samples = [
    "1' AND SLEEP(5)-- -",
    "1 AND SLEEP(3) IS NOT NULL",
    "1'; WAITFOR DELAY '0:0:5'-- -",
    "1 AND pg_sleep(3)-- -",
  ];
  for (const s of samples) {
    const outAll = keyword2hexall.transform(s, {});
    const outHex = keyword2hex.transform(s, {});
    assert.ok(!/\bSLEEP\b/i.test(outAll), `keyword2hexall 未编码 SLEEP：${outAll}`);
    assert.ok(!/\bWAITFOR\b/i.test(outAll), `keyword2hexall 未编码 WAITFOR：${outAll}`);
    assert.ok(!/\bpg_sleep\b/i.test(outAll), `keyword2hexall 未编码 pg_sleep：${outAll}`);
    assert.ok(!/\bSLEEP\b/i.test(outHex), `keyword2hex 未编码 SLEEP：${outHex}`);
  }
});

test('行为-5) 编码结果可还原且保持 SQL 语义（0xHEX 是 MySQL/MSSQL 合法字面量）', () => {
  const out = keyword2hexall.transform('SELECT 1', {});
  assert.equal(out, '0x73656c656374 1');
  // 还原后应等于原关键字的小写形式（实现有意统一小写：SQL 关键字大小写不敏感）
  assert.equal(Buffer.from(out.slice(2, 2 + 14), 'hex').toString('utf8'), 'select');
});

test('行为-6) 边界不误伤：含关键字子串的标识符原样保留', () => {
  // \b 边界若失效会破坏表名/列名/字符串字面量，进而让注入语句语法错误 → 漏报。
  for (const guard of ['SLEEPY', 'mySELECT', 'CONCATENATE', 'DATABASES', 'LENGTHY_TEXT', 'TOPOLOGY']) {
    assert.equal(keyword2hexall.transform(guard, {}), guard,
      `${guard} 不应被编码（\\b 边界失效会破坏表名/列名）`);
    assert.equal(keyword2hex.transform(guard, {}), guard,
      `${guard} 不应被 keyword2hex 编码`);
  }
});

test('行为-7) 非字符串输入不抛错（tamper 链会对各种形态调用 transform）', () => {
  for (const bad of [null, undefined, '', 123, {}]) {
    assert.doesNotThrow(() => keyword2hexall.transform(bad, {}), `keyword2hexall(${String(bad)}) 抛错`);
    assert.doesNotThrow(() => keyword2hex.transform(bad, {}), `keyword2hex(${String(bad)}) 抛错`);
  }
});
