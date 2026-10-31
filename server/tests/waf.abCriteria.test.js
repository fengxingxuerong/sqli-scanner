// waf.abCriteria.test.js —— WAF A/B 装置（e2e/waf-lab）判据的行为 + 接线验证
// ============================================================================
// 起因（2026-09-25，真实现场）：compare-real 装置的 `pass` 只由两条 WAF 侧指标
//   决定（拦截率下降 + 高危规则命中下降），检出侧被当成"无区分度"整个拿掉了。
//   A3 通道降级初版把 CRS 画像下的 error 通道判死，装置里 configA 的检出从
//   1/1 掉到 0/1、请求数 175→246，而退出码仍是 0、报告照印
//   「tamper 确已绕过 WAF ✅」—— 一条"扫描器完全不干活也算通过"的门禁。
//
// 三条主线：
//   ① 纯函数判据：**tamper 侧零检出 ⇒ 实验不成立**，即使两条 WAF 指标都成立也必须红；
//      反向也要成立：检出正常但 WAF 指标不动时，前置不能把它放行。
//      [D221 重校准] 旧前置的「A≥1」在引号结构假阳上标定（2026-09-25）：当时 configA 的
//      1/1 = `1' AND GTID_SUBSET(...)` 打在数值上下文（D207 物证，GTID_SUBSET 从未执行）；
//      modsecurity_crs 档把 union/同义式/extractvalue 族/information_schema 全拦 ⇒
//      A=0 是硬 CRS 档下的诚实结果，tamper 侧（B≥1）才是被测能力 ⇒ 「A=0 且 B≥1」
//      是实验成立的理想形态。A3 通道降级的回归守护由其专项 e2e（决策表精确断言）承担。
//   ② 接线存在：compare-real.e2e.mjs 必须真的调 evaluateAbExperiment，
//      且退出码取自它的 passed（防"helper 写得很全、门禁零调用"）。
//   ③ 前置真的进了 pass 表达式：`passed: valid && …`，摘掉就红。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { evaluateAbExperiment } from '../../e2e/waf-lab/metrics.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '..', '..');

// 2026-09-25 在 HEAD 上实跑一次得到的健康态数字（本文件所有用例的公共基线）
const HEALTHY = {
  totalPoints: 1,
  detectedA: 1,
  detectedB: 1,
  blockRateA: 79.4,
  blockRateB: 45.7,
  highRiskA: 30,
  highRiskB: 0,
};

// —— ① 纯函数判据 ——
test('健康态：前置通过 + 两条 WAF 判据成立 → passed', () => {
  const v = evaluateAbExperiment(HEALTHY);
  assert.equal(v.valid, true);
  assert.deepEqual(v.validityReasons, []);
  assert.equal(v.blockRateDrop, true);
  assert.equal(v.highRiskDrop, true);
  assert.equal(v.passed, true);
});

test('[D221 重校准] 硬 CRS 档理想形态：A=0 且 B≥1（tamper 新增检出）→ 前置通过、实验成立', () => {
  // 旧口径把这条判死（「A3 初版现场复现」）——取证推翻：A=0 在硬 CRS 档是诚实结果。
  // modsecurity_crs 档拦 union select（942100）/ 同义式（942120/130）/ extractvalue 族
  // （942141/142）/ information_schema（942180）⇒ 裸探针无诚实通道可达；
  // configA 旧时的 1/1 是引号结构假阳（`1' AND GTID_SUBSET(...)`，GTID_SUBSET 从未执行，
  // 对照串 `1'-- -` 同签名 ⇒ D211/D212 归因对照正确拒绝）。tamper 侧 B=1 才是被测能力。
  const v = evaluateAbExperiment({ ...HEALTHY, detectedA: 0 });
  assert.equal(v.valid, true, 'A=0 且 B≥1 时前置必须放行（tamper 新增检出 = 实验目的本身）');
  assert.equal(v.blockRateDrop, true);
  assert.equal(v.highRiskDrop, true);
  assert.equal(v.passed, true);
});

test('tamper 侧零检出仍不成立（tamper 把 payload 打成不可执行 ≠ 绕过成功）', () => {
  const v = evaluateAbExperiment({ ...HEALTHY, detectedB: 0 });
  assert.equal(v.valid, false, 'B=0 ⇒ 无从比较，实验不成立（D221 前置核心）');
  assert.equal(v.passed, false);
  assert.match(v.validityReasons.join('\n'), /configB/);
});

test('B=0 且 A=0：双侧全零同样不成立（无任何检出 ⇒ 无从比较）', () => {
  const v = evaluateAbExperiment({ ...HEALTHY, detectedA: 0, detectedB: 0 });
  assert.equal(v.valid, false);
  assert.match(v.validityReasons.join('\n'), /configB/);
});

test('扫描未跑完 / 靶子坏掉：注入点数为 0 时不成立，且理由里带上数字', () => {
  const v = evaluateAbExperiment({ ...HEALTHY, totalPoints: 0, detectedA: 0, detectedB: 0 });
  assert.equal(v.valid, false);
  assert.match(v.validityReasons.join('\n'), /totalPoints=0/);
});

test('反向：检出正常但拦截率未下降 → 前置不得把它放行', () => {
  const v = evaluateAbExperiment({ ...HEALTHY, blockRateB: 79.4 });
  assert.equal(v.valid, true, '检出侧是前置，不是万能通行证');
  assert.equal(v.blockRateDrop, false);
  assert.equal(v.passed, false);
});

test('反向：检出正常但高危规则命中未下降 → 不通过', () => {
  const v = evaluateAbExperiment({ ...HEALTHY, highRiskB: 30 });
  assert.equal(v.valid, true);
  assert.equal(v.highRiskDrop, false);
  assert.equal(v.passed, false);
});

// —— ②③ 接线守卫：门禁必须真调这个函数、且退出码取自它 ——
const SRC = readFileSync(path.join(REPO, 'e2e/waf-lab/compare-real.e2e.mjs'), 'utf8');

test('compare-real.e2e.mjs 必须接上有效性前置（静态守卫）', () => {
  assert.match(SRC, /import \{[^}]*evaluateAbExperiment[^}]*\} from '\.\/metrics\.js'/,
    '入口没引这个函数 = 判据写在 metrics.js 里躺着，门禁照旧空转');
  assert.match(SRC, /= evaluateAbExperiment\(/, '引入了但没调用');
  assert.match(SRC, /const pass = verdict\.passed/, '退出码不得再绕开函数自己拼 criterion');
  assert.match(SRC, /validity:\s*\{\s*value: valid/, '结论字段须落进 JSON 产物，便于事后核对');
});

test('判据必须"前置 && WAF"，把 valid 摘掉即红（缺陷注入守卫）', () => {
  const METRICS_SRC = readFileSync(path.join(REPO, 'e2e/waf-lab/metrics.js'), 'utf8');
  assert.match(METRICS_SRC, /passed: valid && blockRateDrop && highRiskDrop/,
    'evaluateAbExperiment 的实现被改成忽略 valid —— 本文件用例②会红，此处再钉一道');
});
