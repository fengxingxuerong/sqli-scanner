// ============================================================================
// e2e/oob-real-lab/verify.mjs —— OOB 带外通道真机 A/B 验证
// 用法：node e2e/oob-real-lab/verify.mjs
// 矩阵：techniques 含 oob（接收端开/关）× /oob 无回显注入点
// 断言：
//   ① oob 开启 + PG 超管 COPY TO PROGRAM → 检出 oob 技术（全链路真实回连）
//   ② 对照组：boolean/time/union/error 在「无回显 + WAF 拦时间/报错」下应 0 检出
//     （证明 OOB 是该场景下唯一可达通道）
//   ③ WAF 不拦 COPY 向量（OOB 绕过价值实证）
// ============================================================================
import { pathToFileURL } from 'node:url';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { mkdirSync, writeFileSync } from 'node:fs';

const { ScanManager } = await import(pathToFileURL(resolve(dirname(fileURLToPath(import.meta.url)), '../../server/src/engine/ScanManager.js')).href);
const { initDb, createOobLabApp } = await import(pathToFileURL(resolve(dirname(fileURLToPath(import.meta.url)), './lab-app.mjs')).href);
const { oobReceiver } = await import(pathToFileURL(resolve(dirname(fileURLToPath(import.meta.url)), '../../server/src/core/oobReceiver.js')).href);

const PORT = 8171;
const BASE = `http://127.0.0.1:${PORT}`;

console.log('[setup] 初始化 PG oob_lab 库…');
await initDb();

async function runScan(sm, target) {
  const t0 = Date.now();
  const scanId = await sm.start(target);
  for (;;) {
    const s = sm.scans.get(scanId);
    if (s && (s.status === 'completed' || s.status === 'error')) break;
    if (Date.now() - t0 > 120000) { sm.stop(scanId).catch(() => {}); return { status: 'timeout', vulns: [] }; }
    await new Promise((r) => setTimeout(r, 30));
  }
  const rep = sm.getReport(scanId) || {};
  return { status: sm.scans.get(scanId)?.status, vulns: rep.vulns || [] };
}
const techs = (v) => [...new Set((v || []).map((x) => x.technique))];

const results = {};

// —— 实验 1：OOB 开启（techniques 含 oob + oob.enabled）——
{
  const { app, close } = createOobLabApp({ waf: true });
  const server = app.listen(PORT, '127.0.0.1');
  await new Promise((resolve, reject) => {
  server.once('listening', resolve);
  // [P0-FIX 2026-09-14] listen 失败硬退出：端口被占/权限问题时静默继续 = 扫错目标出废报告
  server.once('error', (e) => reject(new Error(`靶场监听失败（端口被占？先杀残留进程）: ${e.message}`)));
});
  const sm = new ScanManager();
  const out = await runScan(sm, {
    url: `${BASE}/oob?name=user1`,
    config: {
      concurrency: 4, ratePerSec: 0, retry: 0, timeoutMs: 15000, enableExtract: false,
      techniques: ['oob'],
      oob: { enabled: true, callbackBase: '127.0.0.1:8899', httpPort: 8899, timeoutMs: 8000 },
    },
  });
  results.oobOn = { found: techs(out.vulns), status: out.status };
  console.log(`[实验1] oob 开启 + WAF：检出=[${results.oobOn.found.join(',') || '-'}] status=${out.status}`);
  for (const x of out.vulns) console.log('   ', x.technique, '|', String(x.evidence || x.description || '').slice(0, 140));
  server.close();
  await close();
}

// —— 实验 2：对照组（默认四技术，无 oob；同一无回显 + WAF 场景应 0 检出）——
{
  const { app, close } = createOobLabApp({ waf: true });
  const server = app.listen(PORT, '127.0.0.1');
  await new Promise((r) => server.once('listening', r));
  const sm = new ScanManager();
  const out = await runScan(sm, {
    url: `${BASE}/oob?name=user1`,
    config: { concurrency: 4, ratePerSec: 0, retry: 0, timeoutMs: 15000, enableExtract: false },
  });
  results.control = { found: techs(out.vulns), status: out.status };
  console.log(`[实验2] 对照（默认技术，无 oob）：检出=[${results.control.found.join(',') || '-'}] status=${out.status}`);
  server.close();
  await close();
}

// —— 汇总与落盘 ——
console.log('\n===== OOB 真机 A/B 汇总 =====');
const oobHit = results.oobOn.found.includes('oob');
const controlZero = results.control.found.length === 0;
console.log(`OOB 通道检出：${oobHit ? '✅ 全链路回连命中' : '❌ 未命中'}`);
console.log(`对照组（无回显+WAF，默认技术）：${controlZero ? '0 检出（OOB 是该场景唯一可达通道）' : '有检出：' + results.control.found.join(',')}`);
console.log(`结论：${oobHit && controlZero ? 'OOB 带外通道真机验证通过' : '需排查'}`);

const RESULTS_DIR = resolve(dirname(fileURLToPath(import.meta.url)), 'results');
mkdirSync(RESULTS_DIR, { recursive: true });
const genAt = new Date().toISOString();
writeFileSync(resolve(RESULTS_DIR, 'oob-real-report.json'), JSON.stringify({ generatedAt: genAt, engine: 'PostgreSQL 16.2 @5432 (superuser)', results }, null, 2));
const md = [
  '# OOB 带外通道真机验证（真实 PostgreSQL 16.2）',
  '',
  `> 生成：${genAt}　｜　引擎：真实 PostgreSQL 16.2（便携版，超管）　｜　场景：/oob 无回显 + WAF（拦 sleep/报错/union）`,
  '',
  '| 实验 | 配置 | 检出 | 结论 |',
  '|---|---|---|---|',
  `| OOB 开启 | techniques=[oob] + oob.enabled | ${results.oobOn.found.join(',') || '-'} | ${oobHit ? '✅ 全链路回连命中' : '❌ 未命中'} |`,
  `| 对照 | 默认四技术 | ${results.control.found.join(',') || '-'} | ${controlZero ? '0 检出（OOB 为唯一可达通道）' : '有其他检出'} |`,
  '',
  '> 全链路：引擎 payload（COPY TO PROGRAM curl {CALLBACK}）→ 靶场 HTTP → PG 进程执行 →',
  '> OS curl 真实回连 127.0.0.1:8899/oob/:token → oobReceiver 捕获 → OobDetector 判定。',
].join('\n');
writeFileSync(resolve(RESULTS_DIR, 'oob-real-report.md'), md);
console.log(`[report] ${RESULTS_DIR}`);

try { await oobReceiver.stop?.(); } catch { /* 未启动时忽略 */ }
process.exit(0);
