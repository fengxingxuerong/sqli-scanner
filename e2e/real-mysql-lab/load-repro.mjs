// ============================================================================
// e2e/real-mysql-lab/load-repro.mjs —— 负载下复现 noisy 布尔漏检（定位工具）
//
// 背景：noisy 场景已登记 flaky（verify.mjs [FLAKY 2026-09-23] + 台账 1/5 复现率）：
// 同一份代码，负载/慢机器下 `检出=[time] miss=[boolean]`。本工具用 CPU 燃烧进程
// 制造负载，反复单扫 /noisy，并对 BooleanBlindDetector._robustDetect 打猴子补丁
// 捕获判定 trace（三一致率/门槛/各样本长度），把「负载到底打断了哪一环」看清楚。
//
// 用法：node e2e/real-mysql-lab/load-repro.mjs [轮数=8] [燃烧进程数=6]
// 环境变量同 verify.mjs（MYSQL_HOST/PORT/USER/PASSWORD/DATABASE、MYSQL_LAB_PORT）
// ============================================================================
import { spawn } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createRequire } from 'node:module';
import { createMysqlLabApp } from './lab-app.js';

const require = createRequire(new URL('../../server/package.json', import.meta.url));
const mysql = require('mysql2/promise');
const { ScanManager } = await import(
  pathToFileURL(resolve(dirname(fileURLToPath(import.meta.url)), '../../server/src/engine/ScanManager.js')).href
);
const { BooleanBlindDetector } = await import(
  pathToFileURL(resolve(dirname(fileURLToPath(import.meta.url)), '../../server/src/engine/detectors/BooleanBlindDetector.js')).href
);

const PORT = Number(process.env.MYSQL_LAB_PORT) || 8141;
const BASE = `http://127.0.0.1:${PORT}`;
const ROUNDS = Number(process.argv[2]) || 8;
const BURNERS = Number(process.argv[3]) || 6;

// —— 猴子补丁：捕获 _robustDetect 的判定轨迹（含 miss 轮）——
const traces = [];
const origRobust = BooleanBlindDetector.prototype._robustDetect;
BooleanBlindDetector.prototype._robustDetect = async function (ctx, result, templates, rb) {
  const r = await origRobust.call(this, ctx, result, templates, rb);
  traces.push({
    vulnerable: r.vulnerable,
    evidence: r.evidence ?? '',
    t: r.trace
      ? {
          noise: r.trace.baselineNoiseRate,
          minStable: r.trace.minStable,
          pairs: (r.trace.pairs ?? []).map((p) => ({
            trueRatio: p.trueRatio,
            falseRatio: p.falseRatio,
            meaningfulRatio: p.meaningfulRatio,
            significant: p.significant,
            tLens: p.trueSamples.map((s) => s.len),
            tLike: p.trueSamples.map((s) => s.likeBaseline),
            fLens: p.falseSamples.map((s) => s.len),
            fLike: p.falseSamples.map((s) => s.likeBaseline),
          })),
        }
      : null,
  });
  return r;
};

const MYSQL_CONF = {
  host: process.env.MYSQL_HOST || '127.0.0.1',
  port: Number(process.env.MYSQL_PORT) || 3306,
  user: process.env.MYSQL_USER || 'root',
  password: process.env.MYSQL_PASSWORD ?? 'root',
  database: process.env.MYSQL_DATABASE || 'sqli_lab',
};
const baseConfig = { concurrency: 4, ratePerSec: 0, retry: 0, timeoutMs: 15000, enableExtract: false };

const pool = mysql.createPool({ ...MYSQL_CONF, connectionLimit: 8, multipleStatements: true });
const app = createMysqlLabApp(pool);
const server = app.listen(PORT, '127.0.0.1');
await new Promise((res, rej) => {
  server.once('listening', res);
  server.once('error', (e) => rej(new Error('靶场端口监听失败: ' + e.message)));
});
console.log(`[load-repro] 靶场就绪 ${BASE}  轮数=${ROUNDS} 燃烧进程=${BURNERS}`);

const sm = new ScanManager();
const startBurners = () => {
  const procs = [];
  for (let i = 0; i < BURNERS; i++) {
    procs.push(spawn(process.execPath, ['-e', 'const t0=Date.now(); while (Date.now()-t0 < 90000) { JSON.parse(JSON.stringify({a:Math.random()})); }']), { stdio: 'ignore' });
  }
  return procs;
};
const killBurners = (procs) => { for (const p of procs) try { p.kill('SIGKILL'); } catch { /* noop */ } };
const techs = (vulns) => [...new Set((vulns ?? []).map((v) => v.technique))];

let missRounds = 0;
for (let round = 1; round <= ROUNDS; round++) {
  const procs = startBurners();
  await new Promise((r) => setTimeout(r, 300)); // 让负载爬起来
  traces.length = 0;
  const t0 = Date.now();
  const scanId = await sm.start({ url: `${BASE}/noisy?uid=1`, config: baseConfig });
  for (;;) {
    const s = sm.scans.get(scanId);
    if (s && (s.status === 'completed' || s.status === 'error')) break;
    if (Date.now() - t0 > 180000) { sm.stop(scanId).catch(() => {}); break; }
    await new Promise((r) => setTimeout(r, 30));
  }
  const rep = sm.getReport(scanId) ?? {};
  const found = techs(rep.vulns);
  killBurners(procs);
  const ok = found.includes('boolean');
  const elapsed = Date.now() - t0;
  if (!ok) missRounds++;
  const tLast = traces.find((t) => t.t && t.t.pairs.length);
  console.log(`[第${round}轮] ${ok ? 'PASS' : 'MISS'}  检出=[${found.join(',') || '-'}]  耗时=${elapsed}ms  noise=${tLast?.t?.noise?.toFixed(2)} minStable=${tLast?.t?.minStable?.toFixed(2)}`);
  if (!ok) {
    for (const t of traces) {
      if (!t.t || t.t.pairs.length === 0) continue;
      console.log(`   └─ robustDetect: vulnerable=${t.vulnerable} noise=${t.t.noise?.toFixed(2)} minStable=${t.t.minStable?.toFixed(2)}`);
      for (const p of t.t.pairs.slice(0, 3)) {
        console.log(
          `      pair true=${p.trueRatio.toFixed(2)} false=${p.falseRatio.toFixed(2)} diff=${p.meaningfulRatio.toFixed(2)} sig=${p.significant}` +
            ` tLens=${JSON.stringify(p.tLens)} tLike=${JSON.stringify(p.tLike)} fLens=${JSON.stringify(p.fLens)} fLike=${JSON.stringify(p.fLike)}`
        );
      }
    }
  }
  await new Promise((r) => setTimeout(r, 500));
}

server.close();
await pool.end().catch(() => {});
console.log(`\n[load-repro] 完成：${ROUNDS} 轮中 ${missRounds} 轮 miss`);
process.exit(missRounds ? 1 : 0);
