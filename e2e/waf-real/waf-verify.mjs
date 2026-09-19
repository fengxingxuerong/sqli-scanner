// ============================================================================
// e2e/waf-real/waf-verify.mjs —— 真实 WAF 实测：OWASP CRS v4.1.0 官方规则 × 真实 MySQL 8.0.28
// 用法：node e2e/waf-real/waf-verify.mjs
// 矩阵：引擎 tamper off / tamper on（on 档实投 ['dash2hash']，见下方 TAMPERS 的口径修正注释）
//       × 场景（num/str/like/orderby/blind/time）+ 安全对照（不应误拦）
// ============================================================================
import { pathToFileURL } from 'node:url';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import { createMysqlLabApp } from '../real-mysql-lab/lab-app.js';

const require = createRequire(new URL('../../server/package.json', import.meta.url));
const mysql = require('mysql2/promise');
const { evaluate, fromExpress } = await import(pathToFileURL(resolve(dirname(fileURLToPath(import.meta.url)), './crs-engine.js')).href);
const { ScanManager } = await import(pathToFileURL(resolve(dirname(fileURLToPath(import.meta.url)), '../../server/src/engine/ScanManager.js')).href);

const PORT = 8150;
const BASE = `http://127.0.0.1:${PORT}`;
const MYSQL_CONF = { host: process.env.MYSQL_HOST ?? '127.0.0.1', port: Number(process.env.MYSQL_PORT) || 3306, user: process.env.MYSQL_USER ?? 'root', password: process.env.MYSQL_PASSWORD ?? 'root', database: process.env.MYSQL_DATABASE || 'sqli_lab' };

let WAF_HITS = 0;
function makeApp() {
  const pool = mysql.createPool({ ...MYSQL_CONF, connectionLimit: 8, multipleStatements: true });
  const crsMiddleware = (req, res, next) => {
    const verdict = evaluate(fromExpress(req));
    if (verdict.blocked) {
      WAF_HITS++;
      res.status(403).send(`<!DOCTYPE html><html><head><title>403 Forbidden</title></head><body><h1>403</h1><p>Request blocked by OWASP CRS rule ${verdict.ruleId}</p></body></html>`);
      return;
    }
    next();
  };
  // CRS 中间件必须先于业务路由注册（createMysqlLabApp 内 preMiddleware 注入点）
  const app = createMysqlLabApp(pool, crsMiddleware);
  return { app, pool };
}

const baseConfig = { concurrency: 4, ratePerSec: 0, retry: 0, timeoutMs: 15000, enableExtract: false };
async function runScan(sm, target) {
  const t0 = Date.now();
  const scanId = await sm.start(target);
  for (;;) {
    const s = sm.scans.get(scanId);
    if (s && (s.status === 'completed' || s.status === 'error')) break;
    if (Date.now() - t0 > 180000) { sm.stop(scanId).catch(() => {}); return { status: 'timeout', vulns: [] }; }
    await new Promise((r) => setTimeout(r, 30));
  }
  const rep = sm.getReport(scanId) || {};
  return { status: sm.scans.get(scanId)?.status, vulns: rep.vulns || [] };
}
const techs = (v) => [...new Set((v || []).map((x) => x.technique))];

const SCENARIOS = [
  { name: 'num', url: '/num?id=1', must: ['union', 'error', 'boolean'], nice: [] },
  { name: 'str', url: '/str?name=alice', must: ['boolean'], nice: ['error'] },
  { name: 'like', url: '/like?q=keyboard', must: ['boolean'], nice: ['error'] },
  { name: 'orderby', url: '/orderby?sort=id', must: ['boolean'], nice: ['error'], cfg: { level: 2 } },
  { name: 'blind', url: '/blind?uid=1', must: ['boolean'], nice: [] },
  { name: 'safe', url: '/safe?id=1', expectSafe: true },
  { name: 'echo', url: '/echo?key=abc', expectSafe: true },
];

// [P2-FIX 2026-09-09] 结构修正：scanRoutes 归一化只认 wafEvasion.tamper.{enabled,plugins}，
// 旧版顶层 {enabled,plugins} 会被静默丢弃 → 旧基线的 "tamper on" 实际从未生效（A/B 无差异的真实原因）。
// 组合修正（三轮静态验证 + A/B 实测产出）：
//   - space2comment：/**/ 是 4 连非词字符，被 942460 拦 → 移除
//   - charencode：942 系规则全带 t:urlDecodeUni，编码必被还原 → 移除
//   - logicalops：AND→&& 被 942120 直接拦（&& 是 CRS 明确检测的 SQL 操作符）→ 移除
//   - dash2hash：-- - → #，布尔向量实测全过 942460/942431 → 唯一保留
const TAMPERS = {
  // [口径修正 2026-09-10] off 必须同时关掉「拦截自适应」，否则它不再是「无规避基线」——
  // 实测 off 档会吃到自动换链（num 3/3），与 on 档互相串味，A/B 失去意义。
  // 自适应路径的独立验收见 waf-auto-check.mjs（npm run waf-auto）。
  // 注意：本表的值**直接就是 wafEvasion 的内容**（调用处为 config.wafEvasion = tamper），
  // 不要再套一层 wafEvasion，否则新键会被当成未知子键静默失效（实测 off 档因此仍吃到自适应）。
  off: { adaptiveOnBlock: false },
  on: { adaptiveOnBlock: false, tamper: { enabled: true, plugins: ['dash2hash'], intensity: 'medium' } },
};

const matrix = {};
for (const [label, tamper] of Object.entries(TAMPERS)) {
  WAF_HITS = 0;
  const { app, pool } = makeApp();
  const server = app.listen(PORT, '127.0.0.1');
  await new Promise((r) => server.once('listening', r));
  const sm = new ScanManager();
  const rows = {};
  for (const sc of SCENARIOS) {
    const cfg = { ...baseConfig, ...(sc.cfg || {}) };
    if (tamper) cfg.wafEvasion = { ...tamper };
    const before = WAF_HITS;
    const out = await runScan(sm, { url: `${BASE}${sc.url}`, config: cfg });
    const found = techs(out.vulns);
    rows[sc.name] = { found, wafBlocked: WAF_HITS - before, elapsedMs: out.elapsedMs, status: out.status };
  }
  server.close();
  await pool.end().catch(() => {});
  matrix[label] = rows;
  const det = SCENARIOS.filter((s) => !s.expectSafe).map((s) => rows[s.name].found.length).reduce((a, b) => a + b, 0);
  const total = SCENARIOS.filter((s) => !s.expectSafe).length;
  // [口径修正 2026-09-19] 原输出 `检出 ${det}/${total} 个技术位` 把两个不同量纲的数放进一个分数里
  // （det=技术位合计、total=场景数），README 于是抄成了「10/5 技术位」。改成两句各说各的。
  console.log(`[tamper ${label}] 技术位合计 ${det}（${total} 个注入场景，每场景可有多个技术位），WAF 拦截请求 ${WAF_HITS} 次`);
  for (const sc of SCENARIOS) {
    const r = rows[sc.name];
    console.log(`  ${sc.name.padEnd(8)} 检出=[${r.found.join(',') || '-'}]  被WAF拦 ${r.wafBlocked} 请求`);
  }
}

// —— 汇总 ——
console.log('\n===== 汇总 =====');
for (const sc of SCENARIOS) {
  if (sc.expectSafe) continue;
  const off = matrix.off[sc.name].found.length;
  const on = matrix.on[sc.name].found.length;
  console.log(`${sc.name.padEnd(8)} tamper off: ${off}/${sc.must.length + 0}  tamper on: ${on}/${sc.must.length}  ${on > off ? '↑ 绕过生效' : off === 0 && on === 0 ? '✗ 全拦' : '—'}`);
}
const safeOk = SCENARIOS.filter((s) => s.expectSafe).every((s) => matrix.off[s.name].found.length === 0 && matrix.on[s.name].found.length === 0);
console.log(`安全对照误拦：${safeOk ? '无 ✅' : '有 ❌'}`);

// —— 结果落盘（对外唯一口径，README「WAF 绕过能力实测口径」引用本产物）——
import { mkdirSync, writeFileSync } from 'node:fs';
const RESULTS_DIR = resolve(dirname(fileURLToPath(import.meta.url)), 'results');
mkdirSync(RESULTS_DIR, { recursive: true });
const genAt = new Date().toISOString();
const summaryRows = SCENARIOS.filter((s) => !s.expectSafe).map((s) => ({
  name: s.name,
  tamperOff: matrix.off[s.name].found,
  tamperOn: matrix.on[s.name].found,
  must: s.must,
}));
const report = { generatedAt: genAt, crs: 'OWASP CRS v4.1.0 (自实现 SecRule 执行器 ≈PL3)', db: `MySQL ${MYSQL_CONF.host}:${MYSQL_CONF.port}/${MYSQL_CONF.database}`, matrix, summaryRows, safeControlFalsePositive: !safeOk };
writeFileSync(resolve(RESULTS_DIR, 'waf-real-report.json'), JSON.stringify(report, null, 2));
const md = [
  '# 真实 CRS v4.1.0 下 tamper 开/关 A/B（对外唯一口径）',
  '',
  `> 生成：${genAt}　｜　靶场：真实 MySQL 8.0.28（e2e/real-mysql-lab/lab-app）　｜　CRS：官方规则原文 + 自实现执行器 ≈PL3`,
  '',
  '| 场景 | tamper 关 | tamper 开 | 结论 |',
  '|---|---|---|---|',
  ...summaryRows.map((r) => `| ${r.name} | ${r.tamperOff.join(',') || '-'} | ${r.tamperOn.join(',') || '-'} | ${r.tamperOn.length > r.tamperOff.length ? '绕过生效' : r.tamperOff.length === 0 && r.tamperOn.length === 0 ? '全拦' : '—'} |`),
  '',
  `安全对照误拦：${safeOk ? '无' : '有（需修）'}`,
  '',
  '> ⚠️ 该执行器为简化版 ModSecurity（无 libinjection @detectSQLi、无排除集），检出强度略低于真实部署，绕过率据此略偏高；商业云 WAF 未实测，禁止据此声明可绕过。',
  '',
].join('\n');
writeFileSync(resolve(RESULTS_DIR, 'waf-real-report.md'), md);
console.log(`[report] ${resolve(RESULTS_DIR, 'waf-real-report.md')}`);
process.exit(0);
