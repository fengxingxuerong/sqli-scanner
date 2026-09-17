// ============================================================================
// e2e/sqlmap-benchmark/run.mjs —— sqlmap 对标评测（Goal Brief: sqlmap-benchmark-parity）
// ============================================================================
// 统一基准：sqli-labs Python 靶场（23 关，SQLite 后端），与本引擎 runner 同一关卡集。
// 双方同条件评测：
//   · 本引擎：ScanManager（techniques: union/error/boolean/time/stacked/inline）
//   · sqlmap 1.10.7：--batch --level=1 --risk=1 --threads=4 --technique=BEUSQ
//     （限定检测型技术，排除枚举/拖库阶段——与「注入检测工具」定位对齐）
// 产出：对比表（关卡/我方检出/我方技术/sqlmap 检出/sqlmap 技术/双方耗时/一致率）
// 写入 docs/sqlmap-benchmark-<date>.md + results JSON。
// ============================================================================
import { spawn } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '../..');
const PORT = Number(process.env.SQLI_LABS_PORT) || 8130;
const BASE = `http://127.0.0.1:${PORT}`;
const OUT_DIR = resolve(ROOT, 'docs/sqlmap-benchmark');
const SM_TIMEOUT = Number(process.env.SM_TIMEOUT_MS) || 60_000;
const SMAP_TIMEOUT = Number(process.env.SQLMAP_TIMEOUT_S) || 120;

const TECHNIQUES = ['union', 'error', 'boolean', 'time', 'stacked', 'inline'];

// [--l3 2026-09-16] 高配对标轮：sqlmap --level=3 --risk=2（检验我方相对高配 sqlmap 的位置，而非只对标浅配置）
const L3_MODE = process.argv.includes('--l3');
const SMAP_LEVEL = L3_MODE ? 3 : 1;
const SMAP_RISK = L3_MODE ? 2 : 1;
const TAG = L3_MODE ? 'level3' : 'level1';
const baseConfig = {
  concurrency: 2, ratePerSec: 0, retry: 0, timeoutMs: 15_000,
  techniques: TECHNIQUES,
  enableExtract: false,
};

// 关卡集（与 sqli-labs-runner.mjs 同步）
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

const fmtMs = (ms) => (ms >= 1000 ? `${(ms / 1000).toFixed(1)}s` : `${ms}ms`);

// ---------- 本引擎 ----------
async function runOurs(sc, { ScanManager }) {
  const sm = new ScanManager();
  const startedAt = Date.now();
  const scanId = await sm.start({ url: `${sc.url}?${sc.param}=1`, config: { ...baseConfig } });
  for (;;) {
    const s = sm.scans.get(scanId);
    if (s && (s.status === 'completed' || s.status === 'error')) break;
    if (Date.now() - startedAt > SM_TIMEOUT) { sm.stop(scanId).catch(() => {}); break; }
    await new Promise((r) => setTimeout(r, 40));
  }
  const rep = sm.getReport(scanId) || {};
  const techs = [...new Set((rep.vulns || []).map((v) => v.technique))];
  return { hit: (rep.vulns || []).length > 0, techs, ms: Date.now() - startedAt, verdict: rep.summary?.verdict || null };
}

// ---------- sqlmap ----------
function runSqlmap(sc) {
  return new Promise((resolveP) => {
    const startedAt = Date.now();
    const args = [
      '-u', `${sc.url}?${sc.param}=1`,
      '--batch', `--level=${SMAP_LEVEL}`, `--risk=${SMAP_RISK}`, '--threads=4',
      '--technique=BEUSQ', '--no-cast', '--flush-session',
      `--output-dir=${resolve(OUT_DIR, 'sqlmap-raw')}`,
      '--timeout=10', '--retries=1',
    ];
    // 注入参数显式指定（-p），避免 sqlmap 启发式跳过
    if (sc.param) args.push('-p', sc.param);
    const proc = spawn('sqlmap', args, { stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '';
    const timer = setTimeout(() => { try { proc.kill('SIGKILL'); } catch { /* noop */ } }, SMAP_TIMEOUT * 1000);
    proc.stdout.on('data', (d) => { out += d.toString(); });
    proc.stderr.on('data', (d) => { out += d.toString(); });
    proc.on('exit', () => {
      clearTimeout(timer);
      const ms = Date.now() - startedAt;
      const techs = [];
      if (/Type: boolean-based blind/i.test(out)) techs.push('boolean');
      if (/Type: time-based blind/i.test(out)) techs.push('time');
      if (/Type: UNION query/i.test(out)) techs.push('union');
      if (/Type: error-based/i.test(out)) techs.push('error');
      if (/Type: stacked queries/i.test(out)) techs.push('stacked');
      if (/Type: inline queries/i.test(out)) techs.push('inline');
      const hit = /is injectable|vulnerable/i.test(out) && techs.length > 0;
      resolveP({ hit, techs, ms });
    });
  });
}

// ---------- 主流程 ----------
async function main() {
  const { ScanManager } = await import(pathToFileURL(resolve(ROOT, 'server/src/engine/ScanManager.js')).href);
  mkdirSync(OUT_DIR, { recursive: true });
  mkdirSync(resolve(OUT_DIR, 'sqlmap-raw'), { recursive: true });

  // 启动靶场
  const pyProc = spawn(process.env.PYTHON_EXE || 'python', [resolve(ROOT, 'e2e/sqli-labs/sqli-labs.py')], {
    env: { ...process.env, SQLI_LABS_PORT: String(PORT) },
    stdio: 'pipe',
  });
  // [P0-FIX] 靶场就绪硬前置：端口可达才开扫（固定 sleep 会被端口占用竞态坑）
  await waitPort(PORT, 30000);
  // [goal 调试] 健康探针：runner 进程视角下靶场必须可达
  try {
    const hr = await fetch(`${BASE}/Less-1/?id=1`);
    const hb = await hr.text();
    console.log(`[探针] L01 健康检查: HTTP ${hr.status}, len=${hb.length}`);
  } catch (e) {
    console.log(`[探针] L01 健康检查失败: ${e.message}`);
  }

  const rows = [];
  try {
    for (const sc of SCENARIOS) {
      const ours = await runOurs(sc, { ScanManager });
      const smap = await runSqlmap(sc);
      const agree = ours.hit === smap.hit;
      rows.push({ id: sc.id, desc: sc.desc, ours, smap, agree });
      const flag = agree ? '==' : '!=';
      console.log(`[${flag}] L${String(sc.id).padStart(2, '0')} ${sc.desc.padEnd(18)} | 我方: ${ours.hit ? ours.techs.join('/') : '未检出'} (${fmtMs(ours.ms)}) | sqlmap: ${smap.hit ? smap.techs.join('/') : '未检出'} (${fmtMs(smap.ms)})`);
    }
  } finally {
    pyProc.kill();
  }

  // 汇总
  const both = rows.filter((r) => r.ours.hit && r.smap.hit).length;
  const oursOnly = rows.filter((r) => r.ours.hit && !r.smap.hit).length;
  const smapOnly = rows.filter((r) => !r.ours.hit && r.smap.hit).length;
  const neither = rows.filter((r) => !r.ours.hit && !r.smap.hit).length;
  const oursRate = (rows.filter((r) => r.ours.hit).length / rows.length * 100).toFixed(1);
  const smapRate = (rows.filter((r) => r.smap.hit).length / rows.length * 100).toFixed(1);
  const agreeRate = (rows.filter((r) => r.agree).length / rows.length * 100).toFixed(1);
  const oursAvgMs = Math.round(rows.filter((r) => r.ours.hit).reduce((a, r) => a + r.ours.ms, 0) / Math.max(1, rows.filter((r) => r.ours.hit).length));
  const smapAvgMs = Math.round(rows.filter((r) => r.smap.hit).reduce((a, r) => a + r.smap.ms, 0) / Math.max(1, rows.filter((r) => r.smap.hit).length));

  console.log(`\n==== [${TAG}] 对标汇总（${rows.length} 关，SQLite 靶场）====`);
  console.log(`双方一致: ${both} | 仅我方: ${oursOnly} | 仅 sqlmap: ${smapOnly} | 双方未检出: ${neither}`);
  console.log(`我方命中率: ${oursRate}% | sqlmap 命中率: ${smapRate}% | 结论一致率: ${agreeRate}%`);
  console.log(`平均耗时（命中场景）: 我方 ${fmtMs(oursAvgMs)} vs sqlmap ${fmtMs(smapAvgMs)}`);

  // 差异原因分析
  const diffs = rows.filter((r) => !r.agree);
  const diffNotes = diffs.map((r) => {
    if (r.ours.hit && !r.smap.hit) {
      return `- L${r.id} ${r.desc}: 我方命中 ${r.ours.techs.join('/')}，sqlmap 未检出（--level=1 浅配置下启发式可能跳过；属 sqlmap 深度配置差异，非我方优势场景）`;
    }
    return `- L${r.id} ${r.desc}: sqlmap 命中 ${r.smap.techs.join('/')}，我方未检出（检出差距项，列入引擎改进 backlog）`;
  });

  const md = [
    `# sqlmap 对标评测报告`,
    '',
    `- 日期：${new Date().toISOString().slice(0, 10)}`,
    '- 基准：sqli-labs Python 靶场（SQLite 后端，23 关）',
    '- 我方：ScanManager（union/error/boolean/time/stacked/inline，level3 等效）',
    '- sqlmap：1.10.7 --batch --level=1 --risk=1 --technique=BEUSQ --no-cast -p <param>',
    '',
    '| 关卡 | 描述 | 我方检出 | 我方技术 | sqlmap 检出 | sqlmap 技术 | 一致 | 我方耗时 | sqlmap 耗时 |',
    '|---|---|---|---|---|---|---|---|---|',
    ...rows.map((r) => `| L${r.id} | ${r.desc} | ${r.ours.hit ? '✅' : '❌'} | ${r.ours.techs.join('/') || '-'} | ${r.smap.hit ? '✅' : '❌'} | ${r.smap.techs.join('/') || '-'} | ${r.agree ? '✅' : '❌'} | ${fmtMs(r.ours.ms)} | ${fmtMs(r.smap.ms)} |`),
    '',
    `## 汇总`,
    '',
    `- 我方命中率：${oursRate}%（${rows.filter((r) => r.ours.hit).length}/${rows.length}）`,
    `- sqlmap 命中率：${smapRate}%（${rows.filter((r) => r.smap.hit).length}/${rows.length}）`,
    `- 结论一致率：${agreeRate}%`,
    `- 双方均命中 ${both} / 仅我方 ${oursOnly} / 仅 sqlmap ${smapOnly} / 双方未检出 ${neither}`,
    `- 平均耗时（命中场景）：我方 ${fmtMs(oursAvgMs)} vs sqlmap ${fmtMs(smapAvgMs)}`,
    '',
    diffs.length ? `## 差异分析\n\n${diffNotes.join('\n')}` : '## 差异分析\n\n无差异——双方结论完全一致。',
    '',
  ].join('\r\n');

  writeFileSync(resolve(OUT_DIR, `sqlmap-benchmark-${new Date().toISOString().slice(0, 10)}-${TAG}.md`), md, 'utf8');
  writeFileSync(resolve(OUT_DIR, `results-${TAG}.json`), JSON.stringify({ rows, summary: { oursRate, smapRate, agreeRate, both, oursOnly, smapOnly, neither, oursAvgMs, smapAvgMs } }, null, 2), 'utf8');
  console.log(`\n报告已写入 ${resolve(OUT_DIR)}`);
}

// ESM pathToFileURL helper
import { pathToFileURL } from 'node:url';
import net from 'node:net';

function waitPort(port, timeoutMs = 30000) {
  return new Promise((resolve, reject) => {
    const t0 = Date.now();
    const tryOnce = () => {
      const s = net.connect(port, '127.0.0.1');
      s.on('connect', () => { s.end(); resolve(true); });
      s.on('error', () => { s.destroy(); if (Date.now() - t0 > timeoutMs) reject(new Error(`靶场端口 ${port} 等待超时`)); else setTimeout(tryOnce, 500); });
    };
    tryOnce();
  });
}
main().catch((e) => { console.error('FATAL:', e); process.exit(1); });
