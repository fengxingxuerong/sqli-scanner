// e2e/recall-lab/false-positive.e2e.js
// ============================================================================
// 假阳性验证（false-positive lab）：扫描「无漏洞」靶场，确认零误报。
//
// 与 recall.e2e.js（受感染靶场验证召回）互补：
//   recall.e2e.js      → 有注入必须检出（召回率）
//   false-positive.e2e → 无注入必须不检出（误报率 = 0）
//
// 流程：同进程启动 safe-lab 靶场 → 逐端点用 ScanManager 真实 HTTP 扫描 →
//       断言漏洞数 = 0
// ============================================================================
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
const { createSafeLab } = await import('./safe-lab-server.js');
const { ScanManager } = await import('../../server/src/engine/ScanManager.js');

const HERE = dirname(fileURLToPath(import.meta.url));
const RESULTS_DIR = resolve(HERE, 'results');
const PORT = Number(process.env.SAFE_LAB_PORT) || 8124;
const BASE = `http://127.0.0.1:${PORT}`;
const SCENARIO_TIMEOUT_MS = 60_000;

// 场景清单：expect=期望漏洞数（全为 0）
const SCENARIOS = [
  { name: 'strict', desc: '数字白名单（非法即 400）', url: `${BASE}/strict?id=1` },
  { name: 'param', desc: '参数化查询语义（无注入面）', url: `${BASE}/param?q=test` },
  { name: 'escape', desc: "单引号转义（'' 无法闭合）", url: `${BASE}/escape?name=alice` },
  { name: 'noecho', desc: '无回显（输入不进入响应）', url: `${BASE}/noecho?id=1` },
  { name: 'json', desc: 'JSON API（数值型回显）', url: `${BASE}/json?key=test` },
];

const baseConfig = {
  concurrency: 2,
  ratePerSec: 0,
  retry: 0,
  timeoutMs: 10_000,
  enableExtract: false,
  techniques: ['union', 'error', 'boolean', 'time'],
};

function fmtMs(ms) { return ms >= 1000 ? `${(ms / 1000).toFixed(1)}s` : `${ms}ms`; }

async function runScan(sm, scenario) {
  const startedAt = Date.now();
  const scanId = await sm.start({ url: scenario.url, config: { ...baseConfig } });
  for (;;) {
    const s = sm.scans.get(scanId);
    if (s && (s.status === 'completed' || s.status === 'error')) break;
    if (Date.now() - startedAt > SCENARIO_TIMEOUT_MS) {
      sm.stop(scanId).catch(() => {});
      return { status: 'timeout', vulns: [], elapsedMs: Date.now() - startedAt };
    }
    await new Promise((r) => setTimeout(r, 20));
  }
  const report = sm.getReport(scanId) || { vulns: [] };
  return {
    status: sm.scans.get(scanId)?.status || 'unknown',
    vulns: report.vulns || [],
    riskLevel: report.riskLevel ?? 'none',
    requests: report.requests ?? null,
    elapsedMs: Date.now() - startedAt,
  };
}

async function main() {
  const { server } = createSafeLab();
  await new Promise((resolveListen) => server.listen(PORT, '127.0.0.1', resolveListen));
  console.log(`[false-positive] safe-lab 已启动：${BASE}`);

  const rows = [];
  let failed = false;

  console.log('=== 假阳性验证：无漏洞目标必须零检出 ===');
  for (const sc of SCENARIOS) {
    try {
      const sm = new ScanManager();
      const out = await runScan(sm, sc);
      const pass = out.vulns.length === 0;
      if (!pass) {
        failed = true;
        console.log(`[FAIL] ${sc.name}（${sc.desc}）检出=${out.vulns.length} 风险=${out.riskLevel} 耗时=${fmtMs(out.elapsedMs)}`);
        for (const v of out.vulns) console.log(`       ↳ technique=${v.technique} point=${v.pointId} evidence=${(v.evidence || '').slice(0, 80)}`);
      } else {
        console.log(`[PASS] ${sc.name}（${sc.desc}）检出=0 风险=${out.riskLevel} 耗时=${fmtMs(out.elapsedMs)}`);
      }
      rows.push({
        scenario: sc.name,
        desc: sc.desc,
        status: out.status,
        vulns: out.vulns.length,
        risk: out.riskLevel,
        elapsedMs: out.elapsedMs,
        pass,
      });
    } catch (e) {
      failed = true;
      console.log(`[FAIL] ${sc.name}（${sc.desc}）扫描异常: ${e.message}`);
      rows.push({ scenario: sc.name, desc: sc.desc, status: 'error', vulns: -1, risk: 'error', elapsedMs: 0, pass: false });
    }
  }

  server.close();

  // 写结果矩阵
  mkdirSync(RESULTS_DIR, { recursive: true });
  const mdRows = rows.map((r) =>
    `| ${r.scenario} | ${r.desc} | ${r.status} | ${r.vulns} | ${r.risk} | ${r.pass ? '✅' : '❌'} |`
  );
  writeFileSync(
    resolve(RESULTS_DIR, 'false-positive.md'),
    `# 假阳性验证矩阵\n\n| 场景 | 描述 | 状态 | 检出 | 风险 | 通过 |\n|---|---|---|---|---|---|\n${mdRows.join('\n')}\n`,
    'utf8'
  );

  console.log(`\n结果: ${rows.filter((r) => r.pass).length}/${rows.length} 通过 → results/false-positive.md`);
  return failed ? 1 : 0;
}

main().then((c) => process.exit(c)).catch((e) => { console.error('FATAL:', e); process.exit(1); });