// ============================================================================
// tests/detectorContract.guard.test.js —— [D257] 检测器统一「插头」的守卫
//
// 守的是四件事（每件都对应一次真实形态的漂移风险）：
//   ① 覆盖：编排总图每个技术位、三个补充验证器、LDAP/XPath 子类都必须声明契约；
//      「加了检测器但没声明靠什么判」在这里红，而不是在报告里长出一个无名证据。
//   ② 不变量：命中必须有证据+载荷、未结论必须与命中互斥且带原因、pointId/technique
//      必须与执行上下文一致 —— 这些都是**报告可信度**的前提，不是格式洁癖。
//   ③ 调度：FAST/SLOW 必须由编排总图派生且与历史常量逐字等价；表里有、调度里没有
//      的检测器会静默不跑（本仓已出过「有入口从不执行」的 D95 形态）。
//   ④ 缺陷复验：Inline 的两条「未结论」路径必须真的标 inconclusive（D257 抓到的
//      假阴性记账缺陷，见 inlineReflectionGateUnusable.test.js 的缺陷-1/2/2b/2c）。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  MATCH_KINDS,
  EXTRACT_KINDS,
  defineDetectorContract,
  assertDetectionResult,
  executeDetector,
  runDetector,
  contractSummary,
} from '../src/engine/detectorSupport/detectorContract.js';
import { STRATEGY_ORDER, FAST_TECHNIQUES, SLOW_TECHNIQUES } from '../src/engine/scan/strategyOrder.js';
import { xmlParamNameDetector } from '../src/engine/detectorSupport/xmlParamName.js';
import { orderByKeyDetector } from '../src/engine/detectorSupport/orderByKey.js';
import { keyBoolDetector } from '../src/engine/detectorSupport/keyBool.js';
import { callProcNameDetector } from '../src/engine/detectorSupport/callProcName.js';
import { LdapXpathInjectionDetector } from '../src/engine/detectors/LdapXpathInjectionDetector.js';
import { Detector } from '../src/engine/Detector.js';
import { createDetectionResult } from '../src/engine/models.js';

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const ERR_CONTRACT = 6012;

/** 补充验证器（不进编排总图，但同样是一等检测器） */
const SUPPORT_DETECTORS = [
  ['xmlParamName', xmlParamNameDetector],
  ['orderByKey', orderByKeyDetector],
  ['keyBool', keyBoolDetector],
  ['callProcName', callProcNameDetector],
  ['ldapXpath', new LdapXpathInjectionDetector()],
];

test('① 覆盖：编排总图每个技术位都声明了判定/提取算子', () => {
  for (const entry of STRATEGY_ORDER) {
    const d = new entry.Detector();
    assert.ok(d instanceof Detector, `${entry.technique}：未继承 Detector（会绕过统一执行器）`);
    assert.equal(d.technique, entry.technique, `${entry.technique}：实例技术位与表不一致`);
    const c = contractSummary(d);
    assert.equal(c.declared, true, `${entry.technique}：未声明契约（match=unspecified）`);
    assert.equal(c.technique, entry.technique, `${entry.technique}：契约 technique 不一致`);
    assert.ok(c.match.length > 0, `${entry.technique}：match 为空`);
    for (const k of c.match) assert.ok(MATCH_KINDS[k], `${entry.technique}：未知 match 类别 ${k}`);
    for (const k of c.extract) assert.ok(EXTRACT_KINDS[k], `${entry.technique}：未知 extract 类别 ${k}`);
  }
});

test('① 覆盖：三个补充验证器 + LDAP/XPath 子类同样声明契约', () => {
  for (const [name, d] of SUPPORT_DETECTORS) {
    const c = contractSummary(d);
    assert.equal(c.declared, true, `${name}：未声明契约`);
    assert.ok(c.match.length > 0, `${name}：match 为空`);
    for (const k of c.match) assert.ok(MATCH_KINDS[k], `${name}：未知 match 类别 ${k}`);
    for (const k of c.extract) assert.ok(EXTRACT_KINDS[k], `${name}：未知 extract 类别 ${k}`);
  }
});

test('② 契约构造期拒绝未知类别 / 缺 match（不等到扫描时才炸）', () => {
  assert.throws(
    () => defineDetectorContract({ technique: 'x', match: 'not-a-kind' }),
    (e) => e.code === ERR_CONTRACT && /未知类别/.test(e.message)
  );
  assert.throws(
    () => defineDetectorContract({ technique: 'x', match: [] }),
    (e) => e.code === ERR_CONTRACT && /未声明判定算子/.test(e.message)
  );
  assert.throws(
    () => defineDetectorContract({ technique: 'x', match: 'echo', extract: ['not-a-kind'] }),
    (e) => e.code === ERR_CONTRACT && /未知类别/.test(e.message)
  );
  assert.throws(() => defineDetectorContract({ technique: '', match: 'echo' }), (e) => e.code === ERR_CONTRACT);
});

test('② 契约是冻结的：运行期改不动（防止某条路径顺手放宽）', () => {
  const c = defineDetectorContract({ technique: 'x', match: ['echo', 'echo'], extract: ['dbms'] });
  assert.deepEqual([...c.match], ['echo'], '重复类别应去重');
  assert.throws(() => { c.match.push('timing'); }, TypeError);
  assert.throws(() => { c.technique = 'y'; }, TypeError);
});

test('③ 结果不变量：合法结果原样通过', () => {
  const ok = {
    ...createDetectionResult('p1', 'error'),
    vulnerable: true,
    evidence: '数据库报错回显：XPATH syntax error',
    payloads: ["' AND extractvalue(1,concat(0x7e,version()))-- -"],
  };
  assert.equal(assertDetectionResult(ok, { technique: 'error', pointId: 'p1' }), ok);
});

test('③ 结果不变量：七类违规必须抛（命中无证据/未结论无原因/串台…）', () => {
  const base = {
    ...createDetectionResult('p1', 'error'),
    vulnerable: true,
    evidence: 'sig',
    payloads: ['p'],
  };
  const meta = { technique: 'error', pointId: 'p1' };
  const cases = [
    ['pointId 串台', { ...base, pointId: 'p2' }],
    ['technique 串台', { ...base, technique: 'union' }],
    ['vulnerable 非布尔', { ...base, vulnerable: 'true' }],
    ['evidence 非字符串', { ...base, evidence: null }],
    ['payloads 非数组', { ...base, payloads: 'p' }],
    ['命中但证据为空', { ...base, evidence: '   ' }],
    ['命中但载荷为空', { ...base, payloads: [] }],
  ];
  for (const [name, bad] of cases) {
    assert.throws(() => assertDetectionResult(bad, meta), (e) => e.code === ERR_CONTRACT, `${name} 未被拦`);
  }
  const inconclusive = { ...createDetectionResult('p1', 'time'), inconclusive: true, inconclusiveReason: '' };
  assert.throws(() => assertDetectionResult(inconclusive, { technique: 'time', pointId: 'p1' }),
    (e) => e.code === ERR_CONTRACT, '未结论缺原因未被拦');
  const both = { ...base, inconclusive: true, inconclusiveReason: 'x' };
  assert.throws(() => assertDetectionResult(both, meta), (e) => e.code === ERR_CONTRACT, '命中+未结论未拦');
});

test('④ 统一执行器：归一化 outcome；契约违规与检测器异常都原样抛出', async () => {
  const ok = {
    ...createDetectionResult('p1', 'error'),
    vulnerable: true,
    evidence: 'sig',
    payloads: ['p'],
  };
  const good = { technique: 'error', detect: async () => ok };
  const out = await executeDetector(good, { point: { id: 'p1' } });
  assert.equal(out.technique, 'error');
  assert.equal(out.result, ok);
  assert.equal(out.vulnerable, true);
  assert.equal(out.unverified, false);
  assert.equal(out.reason, '');

  const unverified = {
    technique: 'time',
    detect: async () => ({ ...createDetectionResult('p1', 'time'), inconclusive: true, inconclusiveReason: '样本不足' }),
  };
  const u = await executeDetector(unverified, { point: { id: 'p1' } });
  assert.equal(u.vulnerable, false);
  assert.equal(u.unverified, true);
  assert.equal(u.reason, '样本不足');

  const bad = { technique: 'error', detect: async () => ({ ...ok, payloads: [] }) };
  await assert.rejects(() => executeDetector(bad, { point: { id: 'p1' } }), (e) => e.code === ERR_CONTRACT);

  const boom = new Error('network down');
  const throws = { technique: 'error', detect: async () => { throw boom; } };
  await assert.rejects(() => executeDetector(throws, { point: { id: 'p1' } }), (e) => e === boom,
    '执行器不得吞掉检测器异常（网络失败要由调度层分类）');
});

test('④ 调度层入口：生产检测器走 run()，鸭子类型测试替身退回 detect()（不绑死测试桩）', async () => {
  const ok = {
    ...createDetectionResult('p1', 'error'),
    vulnerable: true,
    evidence: 'sig',
    payloads: ['p'],
  };
  const prod = { technique: 'error', run: async () => ({ technique: 'error', result: ok, vulnerable: true, unverified: false, reason: '' }) };
  const viaRun = await runDetector(prod, { point: { id: 'p1' } });
  assert.equal(viaRun.result, ok, '有 run() 时必须走统一执行器');

  // 测试替身形态：只有 detect，返回 partial result —— 调度测试大量依赖这一形态
  const double = { technique: 'union', detect: async () => ({ vulnerable: true }) };
  const viaDetect = await runDetector(double, { point: { id: 'p1' } });
  assert.equal(viaDetect.vulnerable, true);
  assert.deepEqual(viaDetect.result, { vulnerable: true });
});

test('⑤ 调度层由编排总图派生，且与历史常量逐字等价', () => {
  assert.deepEqual([...FAST_TECHNIQUES], ['union', 'error', 'boolean', 'inline'], 'FAST 层漂移');
  assert.deepEqual([...SLOW_TECHNIQUES], ['time', 'stacked', 'oob'], 'SLOW 层漂移');
  assert.deepEqual(FAST_TECHNIQUES.filter((t) => SLOW_TECHNIQUES.includes(t)), [], '同一技术位不得同时在两层');
  for (const e of STRATEGY_ORDER) {
    if (e.phase === 'supplemental') {
      assert.equal(e.layer, undefined, `${e.technique}：补充趟不应参与一阶调度层`);
    } else {
      assert.ok(['fast', 'slow'].includes(e.layer), `${e.technique}：一阶检测器缺 layer（会静默不跑）`);
    }
  }
  // 一阶实例集合必须恰好等于两层的并集：多一个=白跑，少一个=漏跑。
  const primary = STRATEGY_ORDER.filter((e) => e.phase !== 'supplemental').map((e) => e.technique).sort();
  const scheduled = [...FAST_TECHNIQUES, ...SLOW_TECHNIQUES].sort();
  assert.deepEqual(scheduled, primary);
});

test('⑤ 接线：detect.js / supplementalRuns 不得回退到手写数组或 detect() 直调', () => {
  const detectSrc = readFileSync(path.join(REPO, 'server/src/engine/scan/detect.js'), 'utf8');
  assert.doesNotMatch(detectSrc, /const FAST = \[/, 'detect.js 又写死了 FAST 数组');
  assert.doesNotMatch(detectSrc, /const SLOW = \[/, 'detect.js 又写死了 SLOW 数组');
  assert.match(detectSrc, /FAST_TECHNIQUES/, 'detect.js 未使用派生的 FAST_TECHNIQUES');
  assert.match(detectSrc, /SLOW_TECHNIQUES/, 'detect.js 未使用派生的 SLOW_TECHNIQUES');
  assert.match(detectSrc, /runDetector\(detector, ctx\)/, '主循环未走统一执行入口');
  assert.doesNotMatch(detectSrc, /await detector\.detect\(ctx\)/, '主循环又直调 detect()（绕过契约）');

  const suppSrc = readFileSync(path.join(REPO, 'server/src/engine/scan/supplementalRuns.js'), 'utf8');
  assert.match(suppSrc, /runDetector\(this\.secondOrderDetector, ctx\)/, '二阶补充趟未走统一执行入口');
  assert.match(suppSrc, /runDetector\(detector, ctx\)/, '非 SQL 补充趟未走统一执行入口');
});

test('⑥ 基类：run() 是统一入口，detect() 未实现时抛（子类必须实现）', async () => {
  assert.equal(typeof Detector.prototype.run, 'function');
  const base = new Detector('base-probe');
  assert.equal(contractSummary(base).declared, false, '基类占位不应被当成已声明');
  await assert.rejects(() => base.run({ point: { id: 'p1' } }), /必须由子类实现/);
});
