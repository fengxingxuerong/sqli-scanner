// ============================================================================
// configDroppedKeys.warn.test.js —— 「白名单内、但值形态不合」的丢弃必须喊出来
// ============================================================================
// 背景：入口对配置笔误只喊一半。
//   · 键名不在白名单 → 早就有 warn（[CFG-REACH 2026-09-20] 从 debug 提上来的）；
//   · 键名**在**白名单、值形态却不合该键的校验 → 此前一声不响。
// 两类的后果完全相同：调用方拿到 200 + scanId，扫描正常跑完，报告写「未检出」，
// 而那项设置根本没进引擎 —— 静默假阴性对扫描器是最贵的一类错。
// 典型写法（都是照 sqlmap 的习惯顺手写的）：
//   matchCode: 200        —— 本仓只收 true 或 {true:false}（Detector 按状态码**差异**判）
//   skipParams: "id,page" —— 本仓只收数组
//   paramDel: ","         —— 窄集合外字符（与默认分隔符歧义）
// 判据本身在 scanConfigUtils.diffDroppedConfigKeys（纯函数），本文件同时钉住纯函数与接线。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { logger } from '../src/core/logger.js';
import { sanitizeStart } from '../src/api/scanRoutes.js';
import { diffDroppedConfigKeys, isTrivialValue } from '../src/api/scanConfigUtils.js';

const URL_TARGET = { url: 'http://shop.example.com/item?id=1' };

/** 收集一次调用期间的 warn，并**把返回值带出来**（丢返回值就等于测不到"告警 vs 落地"是否同源） */
function withWarns(fn) {
  const orig = logger.warn;
  const seen = [];
  logger.warn = (msg) => { seen.push(String(msg)); };
  try {
    return { warns: seen, result: fn() };
  } finally {
    logger.warn = orig;
  }
}

/** 只关心告警文本时用这个 */
function warnsDuring(fn) {
  return withWarns(fn).warns;
}

// ── 纯函数层 ──────────────────────────────────────────────────────────────
const KNOWN = new Set(['matchCode', 'skipParams', 'scope', 'testFilter', 'safeFreq', 'db']);

test('diffDroppedConfigKeys：未知键与"白名单内被丢弃"分两栏报', () => {
  const d = diffDroppedConfigKeys(
    { bogusKey: 1, matchCode: 200, skipParams: 'id,page' },
    KNOWN,
    {},
    new Set(['db'])
  );
  assert.deepEqual(d.unknown, ['bogusKey']);
  assert.deepEqual(d.shapeDropped, ['matchCode', 'skipParams']);
});

test('diffDroppedConfigKeys：合法空值不算丢弃（否则每个正常请求都在刷屏）', () => {
  // scope:[] 就是"不限范围"、testFilter:'' 就是"不过滤" —— 语义上等于没配，不是被拒
  const d = diffDroppedConfigKeys({ scope: [], testFilter: '', bogus: null }, KNOWN, {}, new Set());
  assert.deepEqual(d.shapeDropped, []);
  assert.deepEqual(d.unknown, ['bogus']);
  // 已落地的键不报
  assert.deepEqual(diffDroppedConfigKeys({ matchCode: true }, KNOWN, { matchCode: true }).shapeDropped, []);
  // 直连模式专用键在 HTTP 形态下必然不落地，属设计而非丢弃
  assert.deepEqual(diffDroppedConfigKeys({ db: { a: 1 } }, new Set(['db']), {}, new Set(['db'])).shapeDropped, []);
});

test('isTrivialValue：只把"空"当没配，false / 0 都是有效设置', () => {
  for (const v of [undefined, null, '', '   ', [], {}, '\n']) assert.equal(isTrivialValue(v), true, `${JSON.stringify(v)} 应为平凡值`);
  for (const v of [false, 0, 'x', [1], { a: 1 }]) assert.equal(isTrivialValue(v), false, `${JSON.stringify(v)} 不该被当成没配`);
});

// ── 接线层：真的喊出来了吗 ────────────────────────────────────────────────
test('接线：matchCode 发数字（sqlmap --code 的习惯写法）→ warn 点名该键', () => {
  const seen = warnsDuring(() => sanitizeStart({ target: URL_TARGET, config: { matchCode: 200 } }));
  const hit = seen.filter((m) => m.includes('matchCode'));
  assert.equal(hit.length, 1, `应恰好一条点名 warn，实际：${JSON.stringify(seen)}`);
  assert.match(hit[0], /不会生效/);
});

test('接线：skipParams 发逗号串 → warn 点名该键', () => {
  const seen = warnsDuring(() => sanitizeStart({ target: URL_TARGET, config: { skipParams: 'id,page' } }));
  assert.ok(seen.some((m) => m.includes('skipParams')), `未点名 skipParams：${JSON.stringify(seen)}`);
});

test('接线：合法空值与已生效的键都不产生"被丢弃"warn（噪声预算是硬约束）', () => {
  const payload = {
    level: 1, risk: 2, techniques: ['union', 'error'],
    scope: [], testFilter: '', safeUrl: 'http://ping.example.com/health', safeFreq: 5,
    csrfUrl: 'http://auth.example.com/login', csrfTokenName: 'csrf_token',
    matchCode: true, skipParams: ['debug'], wafEvasion: { tamper: { enabled: true, plugins: ['space2comment'] } },
  };
  const seen = warnsDuring(() => sanitizeStart({ target: URL_TARGET, config: payload }));
  const dropped = seen.filter((m) => m.includes('被丢弃') || m.includes('未知字段'));
  assert.deepEqual(dropped, [], `一份完全合法的面板形态 payload 不该产生任何丢弃告警：${JSON.stringify(dropped)}`);
});

test('接线：未知字段的旧告警不被这次改动弄丢', () => {
  const seen = warnsDuring(() => sanitizeStart({ target: URL_TARGET, config: { evilKey: 1 } }));
  assert.ok(seen.some((m) => m.includes('未知字段') && m.includes('evilKey')));
});

// ── 反向：告警必须与"真的没落地"同源（2026-09-25 补）────────────────────────
// 上面这批"不该喊"的用例全用**面板形态**（`testFilter:''` 属空值、不算丢弃），所以从没踩到
// 兜底键**带真值**这条路。实况是：diffDroppedConfigKeys 一度算在 BACKFILL_SCALAR_KEYS 兜底
// 透传**之前**，于是那 18 个键全体被判成「被丢弃…设置不会生效」，而它们其实都在返回的
// config 里 —— 本轮实测过 delay/testFilter/reqRate/maxReq/hpp/noCast 六个键同时被喊，
// 六个也同时落地。假告警和静默丢弃是同级的错：它把排查的人支使去改一个本来正确的配置。
// 所以这里不抽查几个键，而是**从源码抓全部兜底键**（与 configReachability 守卫同一口径）遍历。
const BACKFILL = (() => {
  // 2026-09-25：配置守卫整段搬到 api/scanConfigGuard.js（HTTP 与直连两条入口共用）。
// 文本锚点于是必须覆盖【入口层这一整簇】——只读 scanRoutes 会让本守卫在搬移后
// 静默找不到 clamp 收敛点（那正是它要防的"文档写了不存在的能力"的反面：假红/假绿都可能）。
const src = readFileSync(new URL('../src/api/scanRoutes.js', import.meta.url), 'utf8') + readFileSync(new URL('../src/api/scanConfigGuard.js', import.meta.url), 'utf8');
  const m = src.match(/const BACKFILL_SCALAR_KEYS = new Set\(\[([\s\S]*?)\]\)/);
  assert.ok(m, '定位不到 BACKFILL_SCALAR_KEYS —— 名单被改名/挪走时本测试要先红');
  return new Set(Array.from(m[1].matchAll(/'([^']+)'/g)).map((x) => x[1]));
})();

test('不变式：兜底键带真值时，"被丢弃/未知字段"告警与落地集不得有交集', () => {
  const cfg = Object.fromEntries([...BACKFILL].map((k) => [k, 1])); // 数字 1 对三类兜底分支都合法
  const { warns: seen, result: out } = withWarns(() => sanitizeStart({ target: URL_TARGET, config: cfg }));
  const notLanded = [...BACKFILL].filter((k) => !(k in out.config));
  assert.deepEqual(notLanded, [], `这些兜底键没落地（本该由兜底透传进 config）：${notLanded.join(', ')}`);
  // 既然 18 个键**全部**进了 config，任何一条丢弃/未知告警都是假告警
  const accused = seen.filter((m) => m.includes('被丢弃') || m.includes('未知字段'));
  assert.deepEqual(accused, [],
    `全部兜底键都已生效，却仍在告警"设置不会生效"（假告警）：${JSON.stringify(accused)}`);
});

test('混合形态：兜底键 + 真·形状不合 → 只点名后者', () => {
  const seen = warnsDuring(() =>
    sanitizeStart({ target: URL_TARGET, config: { delay: 500, reqRate: 10, matchCode: 200, skipParams: 'id,page' } })
  );
  const dropped = seen.find((m) => m.includes('被丢弃')) || '';
  assert.ok(dropped.includes('matchCode') && dropped.includes('skipParams'), `真该喊的没喊：${dropped}`);
  assert.ok(!dropped.includes('delay=') && !dropped.includes('reqRate='),
    `兜底键被误报成丢弃：${dropped}`);
});
