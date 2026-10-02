// ============================================================================
// report.pocVerify.test.js — PoC 复核预期（实战分析 P0-3，2026-10-02）
// ============================================================================
// 存在理由：布尔/时间通道的 PoC 复放后要靠「真/假响应差异」「延迟是否显著」判读——
// 此前交付物只有请求侧（curl/raw），复核人重放后要自己抓两路响应逐字节对拍。
// 现在把检测器判定轮的**真实采样**（trace.pairs[].true/falseSamples、
// trace.injectSamples/baselineSamples，BooleanBlindDetector.js:575-580 与
// TimeBlindDetector.js:325-331 产出）摘成一行「复核预期」进 PoC。
//
// 夹具纪律：trace 用**检测器真实产出的字段形状**（len/excerpt/ms/threshold），
// 漏洞对象经 createVulnerability 真实工厂构造（trace 是其第 6 参，models.js:222）。
// 不许夹具发明字段名——上一版 SARIF 测试就是这么翻车的（report.sarif.test.js 文件头）。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ReportGenerator } from '../src/services/ReportGenerator.js';
import { pocVerifyHint, pocEntries } from '../src/services/reportPoC.js';
import { createInjectionPoint, createVulnerability } from '../src/engine/models.js';
import { buildPocEvidence } from '../src/engine/pocBuilder.js';

const rg = new ReportGenerator();

// —— 检测器真实形状的 trace（字段名与 BooleanBlindDetector/TimeBlindDetector 一致） ——
const BOOL_TRACE = {
  technique: 'boolean',
  adaptive: false,
  baselineNoiseRate: 0.02,
  minStable: 0.99,
  baselineSamples: [{ idx: 0, len: 1234, likeBaseline: true, excerpt: 'Welcome back, admin' }],
  pairs: [
    {
      ti: 0, fi: 0,
      trueSamples: [{ idx: 0, len: 1234, likeBaseline: true, excerpt: 'Welcome back, admin' }],
      falseSamples: [{ idx: 0, len: 1187, likeBaseline: false, excerpt: 'Welcome back, guest' }],
      trueRatio: 1, falseRatio: 0, meaningfulRatio: 0.98, z: 4.1, significant: true, diffs: [],
    },
  ],
  decision: 'vulnerable',
};

const TIME_TRACE = {
  technique: 'time',
  adaptive: true,
  mu: 0.15, sigma: 0.02, threshold: 3, floor: 0.5,
  baselineSamples: [
    { idx: 0, ms: 0.148, failed: false, excerpt: 'ok' },
    { idx: 1, ms: 0.152, failed: false, excerpt: 'ok' },
  ],
  injectSamples: [
    { idx: 0, ms: 6.112, delayed: true, excerpt: 'ok' },
    { idx: 1, ms: 6.105, delayed: true, excerpt: 'ok' },
    { idx: 2, ms: 0.003, failed: true, excerpt: '' }, // 采样失败必须被剔除，不得污染均值
  ],
  stableRatio: 2 / 3,
  decision: 'vulnerable',
};

test('pocVerifyHint 布尔通道：摘真假采样（len + 片段）', () => {
  const v = createVulnerability('p1', 'boolean', 'High', ["1' AND '1'='1", "1' AND '1'='2"], '命中', BOOL_TRACE);
  const line = pocVerifyHint(v);
  assert.ok(line.startsWith('复核预期（检测时采样）：'), line);
  assert.ok(line.includes('真值响应 len=1234、片段「Welcome back, admin」'), line);
  assert.ok(line.includes('假值响应 len=1187、片段「Welcome back, guest」'), line);
  assert.ok(line.includes('真/假响应差异可复现即确认注入'));
});

test('pocVerifyHint 时间通道：基线均值 + 注入采样（剔除 failed）+ 阈值', () => {
  const v = createVulnerability('p1', 'time', 'High', ["1'; WAITFOR DELAY '0:0:6'--"], '命中', TIME_TRACE);
  const line = pocVerifyHint(v);
  assert.ok(line.includes('基线均值 0.15s'), line);
  // 6.105 的 toFixed 在不同浮点舍入下是 6.10/6.11 皆合法 —— 只钉「failed 采样 0.003s
  // 不得混进列表/均值」这个语义，不钉具体末位数字
  assert.ok(/注入采样 6\.1[01]s\/6\.1[01]s/.test(line), line);
  assert.ok(!line.includes('0.00s'), 'failed 采样不得混入');
  assert.ok(line.includes('判定阈值 3.00s'));
});

test('pocVerifyHint 无 trace / 回显类技术 / 无采样 → null（union/error 复放即见，不渲染）', () => {
  assert.equal(pocVerifyHint(null), null);
  assert.equal(pocVerifyHint(createVulnerability('p1', 'union', 'High', ['x'], 'd', null)), null);
  assert.equal(pocVerifyHint(createVulnerability('p1', 'union', 'High', ['x'], 'd', { technique: 'union' })), null);
  assert.equal(pocVerifyHint(createVulnerability('p1', 'boolean', 'High', ['x'], 'd', { technique: 'boolean', pairs: [] })), null);
  assert.equal(
    pocVerifyHint(createVulnerability('p1', 'time', 'High', ['x'], 'd', { technique: 'time', injectSamples: [], baselineSamples: [] })),
    null
  );
});

test('pocVerifyHint excerpt 换行折叠（报告摘录位是单行，不拆行）', () => {
  const trace = {
    technique: 'boolean',
    pairs: [{
      trueSamples: [{ idx: 0, len: 10, likeBaseline: true, excerpt: 'line1\nline2\tend' }],
      falseSamples: [{ idx: 0, len: 12, likeBaseline: false, excerpt: 'x' }],
    }],
  };
  const line = pocVerifyHint(createVulnerability('p1', 'boolean', 'High', ['x'], 'd', trace));
  assert.ok(line.includes('片段「line1 line2 end」'), line);
});

// —— 渲染侧：走 ReportGenerator 真实导出路径（poc 由 buildPocEvidence 真实构造） ——
function makeReport(vuln) {
  const point = createInjectionPoint('url', 'id', '1', { actionUrl: 'http://test.local/p?id=1' });
  const target = {
    mode: 'http', baseUrl: 'http://test.local/p?id=1', method: 'GET',
    bodyParams: {}, cookieParams: {}, headerParams: {}, config: {},
  };
  const v = Object.assign(vuln, {
    param: 'id',
    poc: buildPocEvidence(target, point, vuln.payloads[0], { redactAuth: false }),
  });
  return {
    scanId: 's1', riskLevel: 'High', dbms: 'MySQL',
    startedAt: '2026-10-02T00:00:00.000Z', finishedAt: '2026-10-02T00:00:10.000Z',
    target, points: [point], vulns: [v], data: null, summary: {},
  };
}

test('toMarkdown：PoC 条目下出现「复核预期」行', () => {
  const md = rg.toMarkdown(makeReport(createVulnerability('p1', 'boolean', 'High', ["1' AND '1'='1"], '命中', BOOL_TRACE)));
  assert.ok(md.includes('- 复核预期（检测时采样）：真值响应 len=1234'), md.split('\n').filter((l) => l.includes('复核')).join(' | '));
});

test('toHTML：复核预期行出现且经转义（片段含 HTML 元字符不执行）', () => {
  const trace = {
    technique: 'boolean',
    pairs: [{
      trueSamples: [{ idx: 0, len: 5, likeBaseline: true, excerpt: '<script>alert(1)</script>' }],
      falseSamples: [{ idx: 0, len: 6, likeBaseline: false, excerpt: 'x' }],
    }],
  };
  const html = rg.toHTML(makeReport(createVulnerability('p1', 'boolean', 'High', ['x'], '命中', trace)));
  assert.ok(html.includes('复核预期（检测时采样）'));
  assert.ok(!html.includes('<script>alert(1)'), 'excerpt 里的 script 必须被转义');
  assert.ok(html.includes('&lt;script&gt;'));
});

test('pocEntries：verify 挂在每条条目（含补充 payload 条目），无 trace 时为 null 不渲染', () => {
  const report = makeReport(createVulnerability('p1', 'time', 'High', ["'; WAITFOR--"], '命中', TIME_TRACE));
  const entries = pocEntries(report);
  assert.ok(entries.length >= 1);
  assert.ok(entries.every((it) => it.verify && it.verify.includes('注入采样')));
  const noTrace = makeReport(createVulnerability('p1', 'union', 'High', ['1 UNION SELECT'], '命中', null));
  assert.ok(pocEntries(noTrace).every((it) => it.verify === null));
  const md = rg.toMarkdown(noTrace);
  assert.ok(!md.includes('复核预期'), 'union 等回显类技术不渲染复核预期（零噪声）');
});
