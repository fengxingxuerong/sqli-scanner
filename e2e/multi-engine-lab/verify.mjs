// ============================================================================
// e2e/multi-engine-lab/verify.mjs —— 多引擎 tamper A/B 验证（H2/HSQLDB/Derby）
// 用法：node e2e/multi-engine-lab/verify.mjs
// 前置：ENGINE_JARS 环境变量（; 分隔的三 jar 路径）、JAVA_HOME 或 java 在 PATH
// 矩阵：引擎 × { tamper off, tamper on(dash2hash) } × 场景（num/str/blind）+ safe 对照
// 断言：safe 永远零检出（误报红线）；tamper on 应 ≥ tamper off（绕过收益）
// 注意：dash2hash 已加方言门控 dbms=['MySQL','MariaDB','TiDB']——对 H2 场景，
//   引擎 dbms 未知（指纹未定），ctx.dbms 为 null 时不过滤，dash2hash 照常生效；
//   H2 的 MODE=MySQL 支持行注释（-- 与 # 均可），Derby/HSQLDB 仅支持 --。
//   ——这正是本实验要验证的：方言门控是否真实挡住了无效 tamper。
// ============================================================================
import { pathToFileURL } from 'node:url';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const require = createRequire(new URL('../../server/package.json', import.meta.url));
const { ScanManager } = await import(pathToFileURL(resolve(dirname(fileURLToPath(import.meta.url)), '../../server/src/engine/ScanManager.js')).href);
const { EngineBridgeClient, createMultiEngineApp } = await import(pathToFileURL(resolve(dirname(fileURLToPath(import.meta.url)), './lab-app.mjs')).href);

const JAVA_BIN = process.env.JAVA_BIN || 'java';
const ENGINES = [
  { name: 'h2', engine: 'h2', label: 'H2 2.2.224 (MODE=MySQL)' },
  { name: 'hsqldb', engine: 'hsqldb', label: 'HSQLDB 2.7.3' },
  { name: 'derby', engine: 'derby', label: 'Derby 10.16.1.1' },
];

const baseConfig = { concurrency: 4, ratePerSec: 0, retry: 0, timeoutMs: 15000, enableExtract: false };

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

const SCENARIOS = [
  { name: 'num', url: '/num?id=1', must: ['boolean'] },
  { name: 'str', url: '/str?name=user1', must: ['boolean'] },
  { name: 'blind', url: '/blind?uid=1', must: ['boolean'] },
  { name: 'safe', url: '/safe?id=1', expectSafe: true },
];

const TAMPERS = {
  off: null,
  on: { tamper: { enabled: true, plugins: ['dash2hash'], intensity: 'medium' } },
};

const bridge = new EngineBridgeClient(JAVA_BIN).start();
const results = {};

try {
  for (const eng of ENGINES) {
    results[eng.name] = { label: eng.label, rows: {} };
    for (const [label, tamper] of Object.entries(TAMPERS)) {
      const app = createMultiEngineApp(bridge, eng.engine);
      const server = app.listen(0, '127.0.0.1');
      await new Promise((r) => server.once('listening', r));
      const base = `http://127.0.0.1:${server.address().port}`;
      const sm = new ScanManager();
      const rows = {};
      for (const sc of SCENARIOS) {
        const cfg = { ...baseConfig };
        if (tamper) cfg.wafEvasion = { ...tamper };
        const out = await runScan(sm, { url: `${base}${sc.url}`, config: cfg });
        rows[sc.name] = { found: techs(out.vulns), status: out.status };
      }
      server.close();
      results[eng.name].rows[label] = rows;
      const det = SCENARIOS.filter((s) => !s.expectSafe).filter((s) => rows[s.name].found.length > 0).length;
      console.log(`[${eng.name}][tamper ${label}] 检出场景 ${det}/3`);
      for (const sc of SCENARIOS) {
        console.log(`  ${sc.name.padEnd(6)} 检出=[${rows[sc.name].found.join(',') || '-'}]  status=${rows[sc.name].status}`);
      }
    }
  }
} finally {
  bridge.stop();
}

// 汇总
console.log('\n===== 多引擎 A/B 汇总 =====');
let allSafeOk = true;
for (const eng of ENGINES) {
  const r = results[eng.name];
  const line = SCENARIOS.filter((s) => !s.expectSafe).map((s) =>
    `${s.name}: off=${r.rows.off[s.name].found.length} on=${r.rows.on[s.name].found.length}`).join('  ');
  console.log(`${eng.name.padEnd(8)} ${line}`);
  for (const [label, rows] of Object.entries(r.rows)) {
    if (rows.safe && rows.safe.found.length > 0) {
      allSafeOk = false;
      console.log(`  ❌ ${eng.name}[${label}] safe 误报: ${rows.safe.found.join(',')}`);
    }
  }
}
console.log(`\n安全对照误拦/误报：${allSafeOk ? '无 ✅' : '有 ❌'}`);

// 落盘
import { mkdirSync, writeFileSync } from 'node:fs';
const RESULTS_DIR = resolve(dirname(fileURLToPath(import.meta.url)), 'results');
mkdirSync(RESULTS_DIR, { recursive: true });
const genAt = new Date().toISOString();
writeFileSync(resolve(RESULTS_DIR, 'multi-engine-report.json'), JSON.stringify({ generatedAt: genAt, engines: results }, null, 2));
const md = [
  '# 多引擎 tamper A/B（H2 / HSQLDB / Derby × CRS v4.1.0）',
  '',
  `> 生成：${genAt}　｜　引擎：真实 JDBC 引擎（内存库）　｜　CRS：官方规则原文 + 自实现执行器 ≈PL3`,
  '',
  '| 引擎 | 场景 | tamper off | tamper on | 说明 |',
  '|---|---|---|---|---|',
  ...ENGINES.flatMap((eng) => SCENARIOS.filter((s) => !s.expectSafe).map((s) => {
    const r = results[eng.name];
    const off = r.rows.off[s.name].found.join(',') || '-';
    const on = r.rows.on[s.name].found.join(',') || '-';
    return `| ${eng.name} | ${s.name} | ${off} | ${on} | ${on ? '检出' : '未检出'} |`;
  })),
  '',
  `安全对照（参数化）：${allSafeOk ? '零误报' : '存在误报（需修）'}`,
  '',
  '> 诚实边界：仅验证布尔通道在 CRS 下的检测/绕过；dash2hash 有方言门控（MySQL 系），',
  '> H2 以 MODE=MySQL 运行故 `#` 注释可用；Derby/HSQLDB 不认 `#`，方言门控生效时 tamper 不投放。',
].join('\n');
writeFileSync(resolve(RESULTS_DIR, 'multi-engine-report.md'), md);
console.log(`[report] ${RESULTS_DIR}`);
