// [D205] CLI 侧 AI 报告：开扫前预检 / 目录语义 / 文档渲染 / 纯落盘 / trace 判据压缩。
// 注意：这里用**静态 import**（deadcode 门禁只认静态 import 的引用，动态 import 会被判成死导出）。
// 代价是 AI_REPORT_* 的读取发生在 import 期 —— 下面第一条用例显式断言「shell 里没设这些变量」，
// 设了就直接点名失败，避免出现「环境被污染 → 用例静默变绿/变红」的不可信结果。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, readFileSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import {
  assertAiReportUsable,
  resolveAiReportDir,
  renderAiReportDoc,
  writeAiReportFiles,
  writeAiReport,
} from '../src/services/aiReportCli.js';
import { summarizeTrace } from '../src/services/ReportAI.js';

test('前置：AI_REPORT_* 不得由外部 shell 注入（否则本文件的「未配置」用例不可信）', () => {
  for (const k of ['AI_REPORT_API_BASE', 'AI_REPORT_KEY_1', 'AI_REPORT_KEY_2', 'AI_REPORT_KEY_3']) {
    assert.equal(process.env[k], undefined, `shell 里设了 ${k}，请先 unset 再跑本测试`);
  }
});

test('assertAiReportUsable：未给 --ai-report 时零副作用', () => {
  assert.doesNotThrow(() => assertAiReportUsable({}));
  assert.doesNotThrow(() => assertAiReportUsable(null));
  assert.doesNotThrow(() => assertAiReportUsable({ aiReport: null }));
});

test('assertAiReportUsable：给了 --ai-report 但 env 未配 → 开扫前抛错并点名缺什么', () => {
  assert.throws(() => assertAiReportUsable({ aiReport: true }), /AI_REPORT_API_BASE/);
  assert.throws(() => assertAiReportUsable({ aiReport: 'out/dir' }), /AI_REPORT_KEY_1/);
});

test('resolveAiReportDir：带值用该目录；不带值落在 --out 旁的 ai-report/', () => {
  assert.equal(resolveAiReportDir({ aiReport: 'rel/dir' }), resolve('rel/dir'));

  const asDir = mkdtempSync(join(tmpdir(), 'airpt-'));
  try {
    assert.equal(resolveAiReportDir({ aiReport: null, out: asDir }), join(resolve(asDir), 'ai-report'));
    // --out 是文件 → 取它所在目录
    assert.equal(resolveAiReportDir({ aiReport: null, out: join(asDir, 'report.json') }), join(resolve(asDir), 'ai-report'));
    // --out 以分隔符结尾但目录不存在 → 仍按目录
    assert.equal(resolveAiReportDir({ aiReport: null, out: join(asDir, 'newdir/') }), join(resolve(asDir, 'newdir'), 'ai-report'));
  } finally {
    rmSync(asDir, { recursive: true, force: true });
  }
  // 无 --out → 当前工作目录
  assert.equal(resolveAiReportDir({ aiReport: null }), join(resolve(process.cwd()), 'ai-report'));
});

test('renderAiReportDoc：头部标注来源、模型链、耗时、脱敏态', () => {
  const doc = renderAiReportDoc(
    { content: '# 报告正文', model: 'a/b→c/d', pipeline: 'analyst→writer→reviewer', reviewNote: '✅ 已审阅' },
    { sourceReport: 'scan-1', elapsedMs: 1234, masked: true },
  );
  assert.match(doc, /source report: scan-1/);
  assert.match(doc, /models: a\/b→c\/d/);
  assert.match(doc, /elapsed: 1234ms/);
  assert.match(doc, /已审阅/);
  assert.match(doc, /数据脱敏: 开启/);
  assert.match(doc, /# 报告正文/);
});

test('renderAiReportDoc：AI_REPORT_MASK=0 时头部改标「关闭」', () => {
  const doc = renderAiReportDoc({ content: 'x' }, { masked: false });
  assert.match(doc, /数据脱敏: 关闭/);
});

test('writeAiReportFiles：落 ai-report.md + ai-report.json，元信息带模型链与结论口径', () => {
  const dir = mkdtempSync(join(tmpdir(), 'airpt-'));
  try {
    const report = {
      scanId: 's-205',
      target: { baseUrl: 'http://example.test/x?id=1' },
      summary: { verdict: 'vulnerability_detected' },
      vulns: [{ technique: 'boolean' }, { technique: 'error' }],
    };
    const r = writeAiReportFiles(dir, { content: 'BODY', model: 'm1→m2→m3', reviewNote: 'ok' }, report, { elapsedMs: 42, masked: true });
    assert.ok(statSync(r.file).isFile());
    assert.ok(statSync(r.metaFile).isFile());
    assert.equal(readFileSync(r.file, 'utf-8').includes('BODY'), true);
    const meta = JSON.parse(readFileSync(r.metaFile, 'utf-8'));
    assert.equal(meta.scanId, 's-205');
    assert.equal(meta.verdict, 'vulnerability_detected');
    assert.equal(meta.vulnCount, 2);
    assert.equal(meta.model, 'm1→m2→m3');
    assert.equal(meta.elapsedMs, 42);
    assert.equal(meta.masked, true);
    assert.equal(meta.roles.length, 3);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('writeAiReport：env 未配置时不抛异常，返回 ok:false 并说明缺什么', async () => {
  const r = await writeAiReport({ scanId: 's' }, { aiReport: true });
  assert.equal(r.ok, false);
  assert.match(String(r.error), /AI 网关未配置/);
});

// ── summarizeTrace：把引擎 trace 压成「可复现判据」──
function traceWith(pairs, minStable = 0.66) {
  return { trace: { minStable, pairs } };
}

test('summarizeTrace：无 trace / 无 pairs → null（报告里标注「禁止编造判据」）', () => {
  assert.equal(summarizeTrace({}), null);
  assert.equal(summarizeTrace({ trace: {} }), null);
  assert.equal(summarizeTrace({ trace: { pairs: [] } }), null);
});

test('summarizeTrace：取真/假样本长度 + 有差异那一对的长度差与片段', () => {
  const v = traceWith([{
    trueSamples: [{ idx: 0, len: 100 }, { idx: 1, len: 100 }],
    falseSamples: [{ idx: 0, len: 100 }, { idx: 1, len: 151 }],
    diffs: [
      { idx: 0, lenDelta: 0, firstDiffOffset: -1, changedSnippet: '' },
      { idx: 1, lenDelta: 51, firstDiffOffset: 30, changedSnippet: 'DB error here' },
    ],
    trueRatio: 1, falseRatio: 0.5, z: 2.83, significant: true,
  }]);
  const b = summarizeTrace(v);
  assert.deepEqual(b.trueLens, [100, 100]);
  assert.deepEqual(b.falseLens, [100, 151]);
  assert.equal(b.lenDelta, 51);
  assert.equal(b.firstDiffOffset, 30);
  assert.equal(b.changedSnippet, 'DB error here');
  assert.equal(b.z, 2.83);
  assert.equal(b.minStable, 0.66);
});

test('summarizeTrace：差异片段截断 200 字符（防目标可控内容撑爆 prompt）', () => {
  const b = summarizeTrace(traceWith([{
    trueSamples: [{ len: 1 }], falseSamples: [{ len: 2 }],
    diffs: [{ idx: 0, lenDelta: 1, firstDiffOffset: 0, changedSnippet: 'A'.repeat(500) }],
    trueRatio: 1, falseRatio: 0, z: 3,
  }]));
  assert.equal(b.changedSnippet.length, 200);
});

test('summarizeTrace：缺字段时给 null 而不是 NaN（NaN 进 prompt 会变成 "NaN" 噪声）', () => {
  const b = summarizeTrace(traceWith([{ trueSamples: [{ len: 10 }], falseSamples: [] }]));
  assert.deepEqual(b.trueLens, [10]);
  assert.deepEqual(b.falseLens, []);
  assert.equal(b.lenDelta, null);
  assert.equal(b.z, null);
  assert.equal(b.minStable, 0.66);
});
