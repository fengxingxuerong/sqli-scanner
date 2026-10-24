// [D153 2026-10-25] nextStepHints 单测：钉死「建议只引用既有披露、不造新结论」的边界。
// 每条建议对应 AGENTS §2 的一个读错模式；缺形报告必须零崩溃。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { nextStepHints } from '../src/services/nextStepHints.js';

const kinds = (hints) => hints.map((h) => h.kind);

test('缺形防御：null/空对象/无 summary → 空数组不崩溃', () => {
  assert.deepEqual(nextStepHints(null), []);
  assert.deepEqual(nextStepHints(undefined), []);
  assert.deepEqual(nextStepHints({}), []);
  assert.deepEqual(nextStepHints({ summary: null, vulns: null }), []);
});

test('结论不可信 → fix-session 排第一（阴性结论作废是最高优先级）', () => {
  const hints = nextStepHints({
    summary: { validity: { reliable: false, status: 'session_expired' }, unverifiedSurfaces: [] },
    vulns: [],
  });
  assert.equal(hints[0].kind, 'fix-session');
  assert.ok(hints[0].text.includes('不可信'));
  assert.ok(hints[0].via.includes('--refresh-url'));
});

test('未验证面 → retest-unverified：文案必须说「没测成 ≠ 测了没洞」', () => {
  const hints = nextStepHints({
    summary: { validity: { reliable: true }, unverifiedSurfaces: [{ surface: 'HTTP 请求头' }], unverifiedSentence: 'HTTP 请求头 2/2' },
    vulns: [],
  });
  assert.ok(kinds(hints).includes('retest-unverified'));
  const h = hints.find((x) => x.kind === 'retest-unverified');
  assert.ok(h.text.includes('未完成有效检测'));
  assert.ok(h.via.includes('retest'));
});

test('未覆盖面 → raise-coverage；爬虫降级 → crawl-fallback', () => {
  const hints = nextStepHints({
    summary: {
      validity: { reliable: true },
      unverifiedSurfaces: [],
      uncoveredSurfaces: [{ surface: 'cookie' }],
      crawlBrowserFallback: true,
    },
    vulns: [],
  });
  assert.ok(kinds(hints).includes('raise-coverage'));
  assert.ok(kinds(hints).includes('crawl-fallback'));
});

test('发现未裁决（open 或缺形）→ triage 建议；全部已裁决 → 无 triage 建议', () => {
  const mk = (triages) => ({ summary: { validity: { reliable: true }, unverifiedSurfaces: [] }, vulns: triages.map((t, i) => ({ id: `v${i}`, triage: t })) });
  const open = nextStepHints(mk([{ status: 'open' }, { status: 'confirmed' }]));
  assert.ok(kinds(open).includes('triage'));
  assert.ok(open.find((x) => x.kind === 'triage').text.includes('1/2'));
  const decided = nextStepHints(mk([{ status: 'confirmed' }, { status: 'false_positive' }]));
  assert.ok(!kinds(decided).includes('triage'));
  // attachTriage 恒回填 triage，但历史报告可能没经过它——缺形按未裁决算
  const legacy = nextStepHints({ summary: { validity: { reliable: true } }, vulns: [{ id: 'v1' }] });
  assert.ok(kinds(legacy).includes('triage'));
});

test('dbmsEvidence.caveat 存在 → dbms-caveat 原样引用告警', () => {
  const hints = nextStepHints({
    summary: { validity: { reliable: true }, dbmsEvidence: { caveat: '命中的 DBMS 只有模板适配' } },
    vulns: [{ id: 'v1', triage: { status: 'confirmed' } }],
  });
  const h = hints.find((x) => x.kind === 'dbms-caveat');
  assert.ok(h);
  assert.equal(h.text, '命中的 DBMS 只有模板适配');
});

test('有检出 → export 收尾建议（含 diff 门禁提示）；无检出且覆盖完整 → baseline 建议', () => {
  const found = nextStepHints({ summary: { validity: { reliable: true }, unverifiedSurfaces: [] }, vulns: [{ id: 'v1', triage: { status: 'confirmed' } }] });
  assert.ok(kinds(found).includes('export'));
  assert.ok(!kinds(found).includes('baseline'));
  const clean = nextStepHints({ summary: { verdict: 'no_vulnerability_detected', validity: { reliable: true }, unverifiedSurfaces: [], uncoveredSurfaces: [] }, vulns: [] });
  assert.ok(kinds(clean).includes('baseline'));
  assert.ok(clean.find((x) => x.kind === 'baseline').via.includes('--diff-base'));
});

test('无检出但有未验证面 → 不给 baseline（覆盖不完整不许建基线认证）', () => {
  const hints = nextStepHints({
    summary: { verdict: 'no_vulnerability_detected', validity: { reliable: true }, unverifiedSurfaces: [{ surface: 'x' }] },
    vulns: [],
  });
  assert.ok(!kinds(hints).includes('baseline'));
  assert.ok(kinds(hints).includes('retest-unverified'));
});
