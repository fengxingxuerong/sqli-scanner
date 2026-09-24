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
import { logger } from '../src/core/logger.js';
import { sanitizeStart } from '../src/api/scanRoutes.js';
import { diffDroppedConfigKeys, isTrivialValue } from '../src/api/scanConfigUtils.js';

const URL_TARGET = { url: 'http://shop.example.com/item?id=1' };

/** 收集一次 sanitizeStart 期间的 warn（logger 是共享对象，属性调用可被就地替换） */
function warnsDuring(fn) {
  const orig = logger.warn;
  const seen = [];
  logger.warn = (msg) => { seen.push(String(msg)); };
  try {
    fn();
  } finally {
    logger.warn = orig;
  }
  return seen;
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
