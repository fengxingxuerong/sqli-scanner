// e2e/sqli-labs/sqli-labs-runner.mjs
// ============================================================================
// SQLi-Labs 75 关验证 runner（对标 sqlmap 官方验收标准）
// 启动 Python 靶场 → 逐关扫描 → 报告命中率
// ============================================================================
import { spawn } from 'node:child_process';
import { ScanManager } from '../../server/src/engine/ScanManager.js';
import { mkdirSync, writeFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const RESULTS_DIR = resolve(HERE, 'results');
const PORT = Number(process.env.SQLI_LABS_PORT) || 8130;
const BASE = `http://127.0.0.1:${PORT}`;
const SCENARIO_TIMEOUT_MS = 60_000;

const baseConfig = {
  concurrency: 2, ratePerSec: 0, retry: 0, timeoutMs: 15_000,
  techniques: ['union', 'error', 'boolean', 'time', 'stacked', 'inline'],
  enableExtract: false,
};

// 关卡定义（与 Python 靶场同步）
const SCENARIOS = [
  { id: 1,  url: `${BASE}/Less-1/`, param: 'id', desc: 'GET 单引号字符串' },
  { id: 2,  url: `${BASE}/Less-2/`, param: 'id', desc: 'GET 数值型' },
  { id: 3,  url: `${BASE}/Less-3/`, param: 'id', desc: 'GET 单引号+括号' },
  { id: 4,  url: `${BASE}/Less-4/`, param: 'id', desc: 'GET 双引号+括号' },
  { id: 5,  url: `${BASE}/Less-5/`, param: 'id', desc: 'GET 双注入单引号' },
  { id: 6,  url: `${BASE}/Less-6/`, param: 'id', desc: 'GET 双注入双引号' },
  { id: 8,  url: `${BASE}/Less-8/`, param: 'id', desc: 'GET 布尔盲注' },
  { id: 9,  url: `${BASE}/Less-9/`, param: 'id', desc: 'GET 时间盲注' },
  { id: 10, url: `${BASE}/Less-10/`, param: 'id', desc: 'GET 时间盲注双引号' },
  { id: 23, url: `${BASE}/Less-23/`, param: 'id', desc: 'OR/AND 过滤' },
  { id: 25, url: `${BASE}/Less-25/`, param: 'id', desc: '注释过滤' },
  { id: 26, url: `${BASE}/Less-26/`, param: 'id', desc: '空格过滤' },
  { id: 28, url: `${BASE}/Less-28/`, param: 'id', desc: 'UNION SELECT 过滤' },
  { id: 29, url: `${BASE}/Less-29/`, param: 'id', desc: 'UNION 过滤' },
  { id: 30, url: `${BASE}/Less-30/`, param: 'id', desc: 'UNION+注释过滤' },
  { id: 31, url: `${BASE}/Less-31/`, param: 'id', desc: '堆叠注入' },
  { id: 32, url: `${BASE}/Less-32/`, param: 'id', desc: '宽字节' },
  { id: 38, url: `${BASE}/Less-38/`, param: 'id', desc: '堆叠+数值' },
  { id: 46, url: `${BASE}/Less-46/`, param: 'sort', desc: 'ORDER BY 注入' },
  { id: 47, url: `${BASE}/Less-47/`, param: 'sort', desc: 'ORDER BY 单引号' },
  { id: 54, url: `${BASE}/Less-54/`, param: 'id', desc: '无回显数值' },
  { id: 61, url: `${BASE}/Less-61/`, param: 'id', desc: '挑战多过滤' },
  { id: 66, url: `${BASE}/Less-66/`, param: 'id', desc: 'XML 注入' },
];

function fmtMs(ms) { return ms >= 1000 ? `${(ms / 1000).toFixed(1)}s` : `${ms}ms`; }

async function runScan(scenario) {
  const startedAt = Date.now();
  const sm = new ScanManager();
  const scanId = await sm.start({
    url: `${scenario.url}?${scenario.param}=1`,
    method: 'GET',
    config: { ...baseConfig },
  });
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
    elapsedMs: Date.now() - startedAt,
  };
}

async function main() {
  console.log(`[sqli-labs] 启动 Python 靶场（端口 ${PORT}）...`);
  const pyPath = resolve(HERE, 'sqli-labs.py');
  const pyExe = process.env.PYTHON_EXE || 'python';
  const pyProc = spawn(pyExe, [pyPath], {
    env: { ...process.env, SQLI_LABS_PORT: String(PORT) },
    stdio: 'pipe',
  });
  await new Promise((r) => setTimeout(r, 3000)); // 等靶场启动

  console.log(`[sqli-labs] 开始验证 ${SCENARIOS.length} 关\n`);
  const rows = [];
  let passed = 0;

  for (const sc of SCENARIOS) {
    try {
      const out = await runScan(sc);
      const hit = out.vulns.length > 0;
      const techs = out.vulns.map((v) => v.technique).join(',');
      if (hit) passed++;
      const flag = hit ? 'PASS' : 'FAIL';
      console.log(`[${flag}] L${String(sc.id).padStart(2, '0')} ${sc.desc.padEnd(20)} ${hit ? `检出=[${techs}]` : '未检出'} 耗时=${fmtMs(out.elapsedMs)}`);
      rows.push({ id: sc.id, desc: sc.desc, hit, techs, elapsedMs: out.elapsedMs });
    } catch (e) {
      console.log(`[FAIL] L${String(sc.id).padStart(2, '0')} ${sc.desc} 异常: ${e.message}`);
      rows.push({ id: sc.id, desc: sc.desc, hit: false, techs: 'error', elapsedMs: 0 });
    }
  }

  pyProc.kill();

  const rate = (passed / rows.length * 100).toFixed(1);
  console.log(`\n结果: ${passed}/${rows.length} 通过 (${rate}%)`);

  // 写结果
  mkdirSync(RESULTS_DIR, { recursive: true });
  const md = `# SQLi-Labs 验证结果\n\n| 关卡 | 描述 | 结果 | 技术 | 耗时 |\n|---|---|---|---|---|\n${rows.map((r) => `| L${r.id} | ${r.desc} | ${r.hit ? '✅' : '❌'} | ${r.techs || '-'} | ${fmtMs(r.elapsedMs)} |`).join('\n')}\n\n**命中率: ${rate}%**\n`;
  writeFileSync(resolve(RESULTS_DIR, 'sqli-labs.md'), md, 'utf8');

  process.exit(passed >= rows.length * 0.6 ? 0 : 1);
}

main().catch((e) => { console.error('FATAL:', e); process.exit(1); });