// ============================================================================
// e2e/cross-module-lab/run.e2e.mjs —— 跨模块端到端验收（模块 7）
// ============================================================================
// 覆盖 spec 5.1.3 / 5.2.3 / 5.3.3 / 5.4.3 / 5.6.3 异常场景的端到端验证。
// 本脚本是聚合 runner：逐条调用已写就的集成测试文件，汇总 PASS/FAIL。
//
// 各场景的断言逻辑分布在对应 server/tests/*.test.js 里（HTTP 级真请求），
// 本脚本只做「跑一遍 + 汇总」——避免断言逻辑重复。
//
// 用法：node e2e/cross-module-lab/run.e2e.mjs
// ============================================================================
import { execFileSync } from 'node:child_process';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, '..', '..');

const SCENARIOS = [
  {
    id: '7.1-auth-quota',
    name: '授权配额端到端（声明缺失/目标超限/扇出超限/键碰撞/审计失败）',
    tests: [
      'server/tests/authQuota.test.js',
      'server/tests/exploitRoutes.authDeclaration.test.js',
    ],
  },
  {
    id: '7.2-redaction-all-format',
    name: '脱敏全格式一致性端到端（json/html/markdown/sarif/csv）',
    tests: [
      'server/tests/reportRedaction.test.js',
      'server/tests/reportRedaction.integration.test.js',
    ],
  },
  {
    id: '7.3-ssrf-ipv6',
    name: 'SSRF IPv6 放行端到端（CIDR 放行/云元数据不可豁免/非法 CIDR）',
    tests: ['server/tests/ssrf.ipv6.test.js'],
  },
  {
    id: '7.4-gate-independence',
    name: '门禁独立性（恒绿检测/覆盖率校准/门禁记录）',
    tests: [],
    scripts: [
      { cmd: 'node', args: ['scripts/greenguard-check.mjs', '--selftest'], label: 'greenguard-check --selftest' },
      { cmd: 'node', args: ['scripts/coverage-calibration.mjs', '--selftest'], label: 'coverage-calibration --selftest' },
    ],
  },
  {
    id: '7.5-detection-regression',
    name: '检测增强回归与不夸大守卫（动态基线/verdict 区分）',
    tests: [
      'server/tests/timingBaseline.test.js',
      'server/tests/verdictGuard.test.js',
    ],
  },
];

let totalPass = 0;
let totalFail = 0;
const failures = [];

for (const scenario of SCENARIOS) {
  console.log(`\n▶ ${scenario.id}：${scenario.name}`);
  let scenarioOk = true;

  for (const testFile of scenario.tests) {
    const fullPath = resolve(REPO, testFile);
    try {
      execFileSync('node', ['--test', fullPath], {
        cwd: REPO,
        stdio: ['pipe', 'pipe', 'pipe'],
        env: { ...process.env, AUTH_DECLARATION_STRICT: 'lenient' },
        timeout: 60000,
      });
      console.log(`  ✓ ${testFile}`);
      totalPass++;
    } catch (err) {
      console.log(`  ✗ ${testFile}`);
      totalFail++;
      scenarioOk = false;
      failures.push(`${scenario.id} / ${testFile}: ${err.message?.slice(0, 200) || 'failed'}`);
    }
  }

  for (const script of scenario.scripts || []) {
    try {
      execFileSync(script.cmd, script.args, {
        cwd: REPO,
        stdio: ['pipe', 'pipe', 'pipe'],
        timeout: 30000,
      });
      console.log(`  ✓ ${script.label}`);
      totalPass++;
    } catch (err) {
      console.log(`  ✗ ${script.label}`);
      totalFail++;
      scenarioOk = false;
      failures.push(`${scenario.id} / ${script.label}: ${err.message?.slice(0, 200) || 'failed'}`);
    }
  }

  if (scenarioOk) console.log(`  → ${scenario.id} PASS`);
  else console.log(`  → ${scenario.id} FAIL`);
}

console.log(`\n${'═'.repeat(60)}`);
console.log(`跨模块 E2E：${totalPass} pass / ${totalFail} fail`);
if (failures.length) {
  console.log('失败明细：');
  for (const f of failures) console.log(`  · ${f}`);
}
process.exit(totalFail > 0 ? 1 : 0);