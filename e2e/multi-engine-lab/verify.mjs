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

const { ScanManager } = await import(pathToFileURL(resolve(dirname(fileURLToPath(import.meta.url)), '../../server/src/engine/ScanManager.js')).href);
const { EngineBridgeClient, createMultiEngineApp } = await import(pathToFileURL(resolve(dirname(fileURLToPath(import.meta.url)), './lab-app.mjs')).href);

const JAVA_BIN = process.env.JAVA_BIN || 'java';
// [LAB-FIX 2026-09-20] 加 NO_WAF=1 一档。为什么必须能关掉：本靶场默认挂 CRS，而 CRS 会把
// UNION 哨兵探针整条 403 掉 → **版本回显定库通道在这里从来没被执行过**。于是"HSQLDB/Derby
// 定不了库"这个结论一直缺少可跑的验证手段（TODO §A 第 2 条点了这件事但一直没做）。
// 关掉 WAF 才能把"探针跑不动（真缺陷）"和"探针没被送达（靶场挡的）"分开——
// 这两件事在报告里长得一模一样，都是 dbms=null。
// 报告标题会带上本档口径，避免 NO_WAF 跑出的数字被误当成带 WAF 的既有结论。
const NO_WAF = process.env.NO_WAF === '1' || process.env.NO_WAF === 'true';
const ENGINES = [
  { name: 'h2', engine: 'h2', label: 'H2 2.2.224 (MODE=MySQL)', expect: 'H2' },
  { name: 'hsqldb', engine: 'hsqldb', label: 'HSQLDB 2.7.3', expect: 'HSQLDB' },
  { name: 'derby', engine: 'derby', label: 'Derby 10.16.1.1', expect: 'Derby' },
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
  return { status: sm.scans.get(scanId)?.status, vulns: rep.vulns || [], dbms: rep.dbms || null };
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
      const app = createMultiEngineApp(bridge, eng.engine, { waf: !NO_WAF });
      const server = app.listen(0, '127.0.0.1');
      await new Promise((resolve, reject) => {
  server.once('listening', resolve);
  // [P0-FIX 2026-09-14] listen 失败硬退出：端口被占/权限问题时静默继续 = 扫错目标出废报告
  server.once('error', (e) => reject(new Error(`靶场监听失败（端口被占？先杀残留进程）: ${e.message}`)));
});
      const base = `http://127.0.0.1:${server.address().port}`;
      const sm = new ScanManager();
      const rows = {};
      for (const sc of SCENARIOS) {
        const cfg = { ...baseConfig };
        if (tamper) cfg.wafEvasion = { ...tamper };
        const out = await runScan(sm, { url: `${base}${sc.url}`, config: cfg });
        rows[sc.name] = { found: techs(out.vulns), status: out.status, dbms: out.dbms };
      }
      server.close();
      results[eng.name].rows[label] = rows;
      const det = SCENARIOS.filter((s) => !s.expectSafe).filter((s) => rows[s.name].found.length > 0).length;
      console.log(`[${eng.name}][tamper ${label}] 检出场景 ${det}/3`);
      for (const sc of SCENARIOS) {
        console.log(`  ${sc.name.padEnd(6)} 检出=[${rows[sc.name].found.join(',') || '-'}]  status=${rows[sc.name].status}  定库=${rows[sc.name].dbms || 'null'}`);
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
  // [LAB-FIX 2026-09-20] 汇总里加"定库"列：本靶场此前只报技术位、不报定库结果，
  // 于是"H2/HSQLDB/Derby 到底能不能被识别出来"这个真问题在这里无法回答——
  // 之前那次 H2 结论是靠临时手写探针跑出来的，跑完就没了。写进报告才算可复查的事实。
  const fp = [...new Set(Object.values(r.rows).flatMap((rows) =>
    Object.values(rows).map((x) => x.dbms).filter(Boolean)))];
  const line = SCENARIOS.filter((s) => !s.expectSafe).map((s) =>
    `${s.name}: off=${r.rows.off[s.name].found.length} on=${r.rows.on[s.name].found.length}`).join('  ')
    + `　定库=${fp.join('/') || 'null（未识别）'}`
    + `　期望=${eng.expect || eng.name.toUpperCase()}`;
  console.log(`${eng.name.padEnd(8)} ${line}`);
  if (fp.length && !fp.some((d) => String(d).toLowerCase() === String(eng.expect || eng.name).toLowerCase())) {
    console.log(`  ⚠️ ${eng.name} 定库结果与真实引擎不符：报的是 ${fp.join('/')}（这是**误判**，比定不出库更糟）`);
  }
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
const wafMode = NO_WAF ? 'off（NO_WAF=1）' : 'on（CRS v4.1.0 ≈PL3）';
// [口径隔离 2026-09-20] NO_WAF 档必须写**独立文件名**，不能覆盖默认那份产物。
// 原因很实际：这一档刚跑完时我差点把"关掉 WAF 测出来的数字"当成仓库里那份 CRS-on 基线提交
// ——两档的 dbms 结果本来就不同（CRS 会 403 掉 UNION 哨兵，版本回显通道压根不执行），
// 换掉之后 README/TODO 里引用的基线就悄悄变了口径，而且没有任何东西会报出来。
// 靠"记得注意"防不住，所以按文件名物理隔开。
const SUFFIX = NO_WAF ? '.no-waf' : '';
writeFileSync(resolve(RESULTS_DIR, `multi-engine-report${SUFFIX}.json`), JSON.stringify({ generatedAt: genAt, waf: wafMode, engines: results }, null, 2));
const md = [
  `# 多引擎 tamper A/B（H2 / HSQLDB / Derby）　—　WAF：${wafMode}`,
  '',
  `> 生成：${genAt}　｜　引擎：真实 JDBC 引擎（内存库）　｜　本档 WAF：${wafMode}`,
  '>',
  '> **口径必须先看这行**：WAF=on 时 CRS 会把 UNION 哨兵探针整条 403 掉，**版本回显定库通道',
  '> 根本不会被执行**，所以那一档里的 `dbms=null` 只说明"没定出库"，不能读成"探针在该库上跑不动"。',
  '> 要判探针本身是否可用，跑 `NO_WAF=1`（本文件 [LAB-FIX 2026-09-20]）。两档数字不可互换。',
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
writeFileSync(resolve(RESULTS_DIR, `multi-engine-report${SUFFIX}.md`), md);
console.log(`[report] ${RESULTS_DIR}${SUFFIX ? `（本档口径 WAF=off，文件名带 ${SUFFIX}，不覆盖 CRS-on 基线）` : ''}`);
