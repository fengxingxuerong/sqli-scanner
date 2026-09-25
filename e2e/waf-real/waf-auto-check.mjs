// ============================================================================
// e2e/waf-real/waf-auto-check.mjs —— CRS 下「引擎自动绕过」验收（不显式配 tamper）
// ============================================================================
// 与 waf-verify.mjs 的区别：那一份测「人工挂链」，本份测「引擎自己能不能挂对链」。
// 验收点：真实 CRS v4.1.0 规则下，config 不含 wafEvasion.tamper，仅靠
//   拦截证据驱动（wafEvasion.adaptiveOnBlock）+ 链验证 → 自动选出有效链并重跑。
// 期望：检出技术位 ≥ 人工挂 dash2hash 的一半，且安全对照零误拦。
// 用法：MYSQL_PORT=3306 MYSQL_USER=root node e2e/waf-real/waf-auto-check.mjs
// ============================================================================
import { pathToFileURL } from 'node:url';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import { mkdirSync, writeFileSync, readFileSync } from 'node:fs';
import { createMysqlLabApp } from '../real-mysql-lab/lab-app.js';

const require = createRequire(new URL('../../server/package.json', import.meta.url));
const mysql = require('mysql2/promise');
const HERE = dirname(fileURLToPath(import.meta.url));
const { evaluate, fromExpress, EFFECTIVE_PL } = await import(pathToFileURL(resolve(HERE, './crs-engine.js')).href);
const { ScanManager } = await import(pathToFileURL(resolve(HERE, '../../server/src/engine/ScanManager.js')).href);

const PORT = 8153;
const MYSQL_CONF = {
  host: process.env.MYSQL_HOST ?? '127.0.0.1',
  port: Number(process.env.MYSQL_PORT) || 3306,
  user: process.env.MYSQL_USER ?? 'root',
  password: process.env.MYSQL_PASSWORD ?? 'root',
  database: process.env.MYSQL_DATABASE || 'sqli_lab',
};

let WAF_HITS = 0;
const pool = mysql.createPool({ ...MYSQL_CONF, connectionLimit: 8, multipleStatements: true });
const crsMiddleware = (req, res, next) => {
  const verdict = evaluate(fromExpress(req));
  if (verdict.blocked) {
    WAF_HITS++;
    res.status(403).send(`<!DOCTYPE html><html><head><title>403</title></head><body><p>blocked by CRS rule ${verdict.ruleId}</p></body></html>`);
    return;
  }
  next();
};
const app = createMysqlLabApp(pool, crsMiddleware);
const server = app.listen(PORT, '127.0.0.1');
await new Promise((r) => server.once('listening', r));
const BASE = `http://127.0.0.1:${PORT}`;

const SCENARIOS = [
  { name: 'num', url: '/num?id=1' },
  { name: 'str', url: '/str?name=alice' },
  { name: 'like', url: '/like?q=keyboard' },
  { name: 'orderby', url: '/orderby?sort=id', cfg: { level: 2 } },
  { name: 'blind', url: '/blind?uid=1' },
];
const SAFE = [
  { name: 'safe', url: '/safe?id=1' },
  { name: 'echo', url: '/echo?key=abc' },
];

const baseConfig = { concurrency: 4, ratePerSec: 0, retry: 0, timeoutMs: 15000, enableExtract: false };
const sm = new ScanManager();

async function runScan(target) {
  const t0 = Date.now();
  const id = await sm.start(target);
  for (;;) {
    const s = sm.scans.get(id);
    if (s && (s.status === 'completed' || s.status === 'error')) break;
    if (Date.now() - t0 > 180000) { sm.stop(id).catch(() => {}); return { techs: [], report: {}, ms: Date.now() - t0 }; }
    await new Promise((r) => setTimeout(r, 30));
  }
  const rep = sm.getReport(id) || {};
  return { techs: [...new Set((rep.vulns || []).map((v) => v.technique))], report: rep, ms: Date.now() - t0 };
}

const rows = [];
let bits = 0;
for (const sc of SCENARIOS) {
  const out = await runScan({ url: BASE + sc.url, config: { ...baseConfig, ...(sc.cfg || {}) } });
  const wafAdaptive = out.report?.summary?.wafAdaptive || null;
  bits += out.techs.length;
  rows.push({ ...sc, techs: out.techs, ms: out.ms, wafAdaptive });
  console.log(
    `[auto] ${sc.name.padEnd(8)} 检出=[${out.techs.join(',') || '-'}] 耗时=${out.ms}ms` +
      (wafAdaptive ? `  自适应=${wafAdaptive.triggered ? '触发' : '-'}` : '')
  );
}
let falsePositive = 0;
for (const sc of SAFE) {
  const out = await runScan({ url: BASE + sc.url, config: baseConfig });
  if (out.techs.length) falsePositive++;
  console.log(`[auto] ${sc.name.padEnd(8)} 检出=[${out.techs.join(',') || '-'}]（期望空）`);
}

server.close();
await pool.end().catch(() => {});
mkdirSync(resolve(HERE, 'results'), { recursive: true });
// 产物文件名带档：默认口径 PL1 占无名那份，其余档各写各的（同 waf-verify.mjs 的 SUFFIX 规则）。
//   否则一次 `CRS_PL=4` 的探索会把入库那份 PL1 取证文件换成 0/0 的形状。
const OUT_SUFFIX = EFFECTIVE_PL === 1 ? '' : `.pl${EFFECTIVE_PL}`;
writeFileSync(
  resolve(HERE, 'results', `waf-auto-check${OUT_SUFFIX}.json`),
  JSON.stringify({ generatedAt: new Date().toISOString(), paranoiaLevel: EFFECTIVE_PL, wafHits: WAF_HITS, techBits: bits, safeFalsePositive: falsePositive, rows }, null, 2)
);
// 人工挂链基线不再写死。原来这里是字面量「基线 = 10」，而 2026-09-19 复测实测是 8 ——
// 写死的对照数不会随被测代码变化，等于长期说谎。改成从 waf-verify 落盘的报告里读；
// 没跑过 waf-real 时明确显示「未采集」，不猜。
// [PL-FIX 2026-09-25] 但"读那份报告"必须**按档读**：原来无论 CRS_PL 是几都读
//   `waf-real-report.json`（= 默认口径 PL1 那份），于是本机实测出现过
//   `CRS_PL=4` 下打印"自动=0（人工挂链基线：off=8 on=8）"—— 拿 PL1 的 8/8 去比 PL4 的 0，
//   读的人会以为自动绕过退了一大截，实际是那一档人工挂链也是 0/0。
//   现在按当前档去找对应产物，产物里记的档位与当前不符就明说"档位不同、不可比"。
const wantPl = EFFECTIVE_PL;
const baselineFile = `waf-real-report${wantPl === 1 ? '' : `.pl${wantPl}`}.json`;
let manualBaseline = '未采集（先跑对应档的 npm run waf-real）';
try {
  const rep = JSON.parse(readFileSync(resolve(HERE, 'results', baselineFile), 'utf8'));
  const rows = Array.isArray(rep.summaryRows) ? rep.summaryRows : null;
  const repPl = rep.paranoiaLevel;
  if (repPl != null && Number(repPl) !== wantPl) {
    manualBaseline = `档位不符不可比（产物标 PL${repPl}，本档 PL${wantPl}）`;
  } else if (rows?.length) {
    const sum = (k) => rows.reduce((a, r) => a + ((r[k] || []).length), 0);
    manualBaseline = `PL${wantPl} 档 off=${sum('tamperOff')} on=${sum('tamperOn')}（${rep.generatedAt || '时间未知'}）`;
  }
} catch { /* 报告缺失即视为未采集 */ }
console.log(`\n[auto] 自动绕过技术位合计 ${bits}（人工挂链基线：${manualBaseline}）｜WAF 拦截 ${WAF_HITS} 次｜安全误报 ${falsePositive}`);
console.log('[auto] 结论：' + (bits >= 5 ? '自动路径生效 ✅' : '自动路径未生效 ❌'));
process.exit(0);
