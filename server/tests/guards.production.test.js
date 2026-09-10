// ============================================================================
// tests/guards.production.test.js —— 生产护栏：能力可见 + 不可逆动作有确认
// [P0-FIX 2026-09-09]
//
// 这一族缺陷的共同形状：开关存在、引擎支持、语义不明 —— 于是
//   ① `risk=3` 在扁平路径上「什么都没做」，用户以为已经测过高危向量（假安心）；
//   ② `risk=3` 在注册表路径上「直接投放写文件/RCE」，没有任何二次确认（真伤害）；
//   ③ 二阶 `secondMethod` 可以是 TRACE/CONNECT/带 CRLF 的任意串（越出「只读复核」的说法）。
// 三条都必须在测试里钉住，因为它们都不会崩，只会静默地给出错误结论或打出错误的包。
// ============================================================================

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  selectPayloads,
  isDestructivePayload,
  runWithDestructivePolicy,
  countDestructiveCandidates,
} from '../src/engine/payloadRegistry.js';
import { collectCapabilityConstraints } from '../src/engine/ScanManager.js';
import {
  resolveSecondOrderMethod,
  SECOND_ORDER_ALLOWED_METHODS,
} from '../src/engine/secondOrderMethod.js';
import { ReportGenerator } from '../src/services/ReportGenerator.js';

const sel = (o = {}) => selectPayloads({ dbms: 'MySQL', technique: 'stacked', level: 5, risk: 3, ...o });
const destructiveOf = (list) => list.filter(isDestructivePayload);

// ── 1) 高危池投放门 ─────────────────────────────────────────────────────────
test('生产模式（默认）未确认：高危模板一条不投', () => {
  const list = sel({ productionMode: true, confirmDestructive: false });
  assert.equal(destructiveOf(list).length, 0, 'productionMode=true 且未 confirmDestructive 时不得投放高危池');
  assert.ok(list.length > 0, '只读模板仍应正常投放（护栏不能把整族检测关掉）');
});

test('显式确认后投放；productionMode=false 保持旧语义', () => {
  assert.ok(destructiveOf(sel({ productionMode: true, confirmDestructive: true })).length > 0);
  assert.ok(destructiveOf(sel({ productionMode: false })).length > 0, '脱离护栏（靶场）时 risk>=3 即投放');
});

test('扫描级策略经 AsyncLocalStorage 下发（检测器无需手工透传）', () => {
  // 无显式入参时，selectPayloads 必须读当前扫描上下文的策略；
  // 这条是「新增出口/治理类配置只改一处」的关键：靠调用点逐个透传必然再漂。
  const suppressed = runWithDestructivePolicy(
    { productionMode: true, confirmDestructive: false },
    () => destructiveOf(sel({})).length
  );
  const allowed = runWithDestructivePolicy(
    { productionMode: false },
    () => destructiveOf(sel({})).length
  );
  assert.equal(suppressed, 0);
  assert.ok(allowed > 0);
});

test('countDestructiveCandidates 只在真有候选时才值得记约束', () => {
  const n = countDestructiveCandidates({ level: 5, risk: 3 });
  assert.ok(n > 0, 'level5/risk3 应能命中高危候选');
  // level 1 时高危模板（level>=3）投不到 → 不该给用户一条「高危池被抑制」的假线索
  assert.equal(countDestructiveCandidates({ level: 1, risk: 1 }), 0);
});

// ── 2) 抑制项必须在报告里可见 ───────────────────────────────────────────────
test('risk=3 未确认 → constraints 记录抑制；确认后不记录', () => {
  const cfg = { risk: 3, level: 5, useRegistry: true, productionMode: true, confirmDestructive: false };
  const notes = collectCapabilityConstraints(cfg);
  assert.ok(notes.some((x) => /高危 payload 池/.test(x) && /27|\d+ 条候选/.test(x)), JSON.stringify(notes));
  assert.equal(collectCapabilityConstraints({ ...cfg, confirmDestructive: true }).length, 0);
});

test('risk=3 + 扁平路径：明确告知「本路径不投放」', () => {
  const notes = collectCapabilityConstraints({ risk: 3, level: 5, useRegistry: false, confirmDestructive: true });
  assert.ok(notes.some((x) => /扁平 payload 路径/.test(x)), JSON.stringify(notes));
});

test('二阶启用但未放行写请求 → 记约束；enableExtract 给提示', () => {
  const notes = collectCapabilityConstraints({
    risk: 2,
    secondOrder: { enabled: true, allowWrites: false },
    productionMode: true,
  });
  assert.ok(notes.some((x) => /二阶非幂等写请求/.test(x)), JSON.stringify(notes));
  const withWrites = collectCapabilityConstraints({
    risk: 2,
    secondOrder: { enabled: true, allowWrites: true },
    productionMode: true,
  });
  assert.ok(!withWrites.some((x) => /二阶非幂等/.test(x)));
  const dump = collectCapabilityConstraints({ risk: 2, enableExtract: true });
  assert.ok(dump.some((x) => /拖库/.test(x)));
  // 默认配置（risk=2、无二阶、无拖库）不应产生任何噪声
  assert.deepEqual(collectCapabilityConstraints({ risk: 2 }), []);
});

test('报告首屏渲染 constraints（HTML 转义、Markdown 成节）', () => {
  const rg = new ReportGenerator();
  const report = {
    scanId: 's1',
    riskLevel: 'Low',
    dbms: 'MySQL',
    target: { baseUrl: 'http://target.test/?id=1' },
    points: [],
    vulns: [],
    summary: {
      verdict: 'inconclusive',
      verdictNote: '未检出漏洞 ≠ 无漏洞：目标连续超时',
      constraints: ['高危 payload 池已抑制：<script>alert(1)</script>'],
    },
  };
  const md = rg.toMarkdown(report);
  assert.match(md, /结论可信度与本次抑制项/);
  assert.match(md, /不可判定（inconclusive）/);
  assert.match(md, /高危 payload 池已抑制/);
  const html = rg.toHTML(report);
  assert.match(html, /结论不可信：未检出 ≠ 无漏洞/);
  assert.ok(!html.includes('<script>alert(1)</script>'), 'constraints 必须转义（报告是会被浏览器打开的文件）');
  assert.match(html, /&lt;script&gt;/);
  // 旧报告（无 summary 字段）不得凭空冒出这一节
  const plain = rg.toMarkdown({ ...report, summary: {} });
  assert.ok(!plain.includes('结论可信度与本次抑制项'));
});

// ── 3) 二阶方法白名单 ───────────────────────────────────────────────────────
test('二阶方法：白名单外回落 GET 并留原因（不抛崩整轮检测）', () => {
  const bad = resolveSecondOrderMethod('TRACE', { productionMode: true });
  assert.equal(bad.method, 'GET');
  assert.equal(bad.skipped, false);
  assert.match(bad.reason, /不支持的二阶请求方法/);
  assert.equal(resolveSecondOrderMethod(null, {}).method, 'GET', '未配置时保持历史行为');
  assert.equal(resolveSecondOrderMethod('get', {}).method, 'GET', '大小写归一');
});

test('二阶方法：CRLF 不得进入请求行', () => {
  const r = resolveSecondOrderMethod('POST\r\nX-Evil: 1', { productionMode: false, allowWrites: true });
  assert.ok(!/[\r\n]/.test(r.method), `方法名里不能残留换行：${JSON.stringify(r.method)}`);
  assert.ok(SECOND_ORDER_ALLOWED_METHODS.includes(r.method) || r.method === 'GET');
});

test('二阶方法：生产模式下非幂等方法需要 allowWrites 才放行', () => {
  const blocked = resolveSecondOrderMethod('POST', { productionMode: true, allowWrites: false });
  assert.equal(blocked.skipped, true);
  assert.match(blocked.reason, /allowWrites/);
  const ok = resolveSecondOrderMethod('POST', { productionMode: true, allowWrites: true });
  assert.equal(ok.skipped, false);
  assert.equal(ok.method, 'POST');
  // 幂等方法无需确认（否则二阶默认路径全被关掉，属过度伤害）
  assert.equal(resolveSecondOrderMethod('HEAD', { productionMode: true }).skipped, false);
  // 脱离护栏（靶场）时不再拦
  assert.equal(resolveSecondOrderMethod('DELETE', { productionMode: false }).skipped, false);
});
