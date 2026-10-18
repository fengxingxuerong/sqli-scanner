// ============================================================================
// e2e/param-mine-lab/sqlmap-contrast.mjs —— [D102] 参数挖掘「同题对照」证据器（本地，非门禁）
//
// 为什么：台账 `paramminer-superiority`（原表述「参数挖掘强于 sqlmap」）在 D68 复核被判
// 表述失真——sqlmap **没有主动挖掘**能力（只收 -p/--param-del 等显式参数），「更强」无定义。
// 本脚本把口径落成可复跑的**同题实测**（redteam-lab 方法论：双方各跑 3 轮取多数决）：
//   · 我方：`?id=1` 零告知，--param-mine 从零发现隐藏参数并检出（复用 run.mjs 判据）
//   · sqlmap-零告知：同一 URL（无 kw），不给任何参数清单 ⇒ 预期 0 检出（它无法发现未告知参数）
//   · sqlmap-全告知：`?id=1&kw=1`（参数已出现在请求里，等价于 -p 全量）⇒ 预期检出 kw
//     可注入（阳性对照：证明靶点真可注入、sqlmap 能力本身没问题——差异在**发现环节**）
// 结论口径（改写后）：能力差异 = 「从零发现」vs「须显式告知」，不是「更强」。
//
// 依赖：sqlmap（SQLMAP_BIN 或 PATH）、MySQL（沙箱跑：python e2e/run-with-sandbox.py
// e2e/param-mine-lab/sqlmap-contrast.mjs）、本目录 run.mjs 与我方侧同一份判据。
// 产物：results-sqlmap-contrast.json（台账 evidence 引用的落盘凭据）。
// 用法：node e2e/param-mine-lab/sqlmap-contrast.mjs [--runs=3]
// ============================================================================
import { spawn, spawnSync } from 'node:child_process';
import { writeFileSync, mkdirSync } from 'node:fs';
import net from 'node:net';
import { fileURLToPath } from 'node:url';

const PORT = Number(process.env.PARAMMINE_LAB_PORT || 8126);
const BASE = `http://127.0.0.1:${PORT}`;
const RUNS = Math.max(1, Number((process.argv.find((a) => a.startsWith('--runs=')) || '').split('=')[1]) || 3);
const SQLMAP = process.env.SQLMAP_BIN || 'sqlmap';
const OUTDIR = fileURLToPath(new URL('./sqlmap-out/', import.meta.url));
const RESULTS = fileURLToPath(new URL('./results-sqlmap-contrast.json', import.meta.url));

const portOpen = (port) => new Promise((resolve) => {
  const s = net.connect(port, '127.0.0.1');
  s.on('connect', () => { s.end(); resolve(true); });
  s.on('error', () => { s.destroy(); resolve(false); });
});

/** sqlmap 单跑：命中判定沿用修正后的 redteam-lab sqlmap-bench 同款「肯定式专有短语」正则与防误报护栏 */
function sqlmapRun(url) {
  return new Promise((resolve) => {
    const verbose = process.env.SQLMAP_VERBOSE || '0';
    // 默认 --level 2：默认档(1)对被 LIKE 字符串拼接 + 通用错误页的形态会漏测（实测 0/3）；
    // 对照两端同参（公平阳性对照：证明靶点可注入、sqlmap 能力本身没问题，差异只在发现环节）。
    const level = process.env.SQLMAP_LEVEL || '2';
    const args = [url, '--batch', '--flush-session', '-v', verbose, '--ignore-proxy',
      '--level', level, '--dbms=mysql',
      '--output-dir', OUTDIR, '--answers=follow=Y'];
    // 清除环境代理：sqlmap 会读 *_PROXY；--ignore-proxy 再兜一层（与 sqlmap-bench 同款冗余）
    const env = { ...process.env };
    for (const k of Object.keys(env)) if (/^(http|https|all)_proxy$/i.test(k)) delete env[k];
    let p;
    try {
      p = spawn(SQLMAP, args, { env, stdio: ['ignore', 'pipe', 'pipe'] });
    } catch (e) {
      resolve({ miss: true, spawnError: e && e.message, out: '' });
      return;
    }
    let out = '';
    p.stdout.on('data', (d) => { out += d; });
    p.stderr.on('data', (d) => { out += d; });
    const guard = setTimeout(() => { try { p.kill('SIGKILL'); } catch { /* noop */ } }, 240000);
    p.on('error', (e) => { clearTimeout(guard); resolve({ miss: true, spawnError: e && e.message, out }); });
    p.on('close', () => {
      clearTimeout(guard);
      // ⚠ 不要用裸 /injectable/ 判命中：sqlmap 没找到时会打
      // `[CRITICAL] all tested parameters do not appear to be injectable` —— 裸词匹配
      // 会把「未检出」判成「检出」（redteam-lab 的 sqlmap runner 就栽在这：6/7 假阳性；
      // D102 已修正，见 e2e/redteam-lab/sqlmap-bench.mjs 与 rescore-sqlmap-logs.mjs）。
      // 只认肯定式专有短语（与修正后的 bench 同款；不用 pos&&!neg——多参数混合日志会反向误杀）。
      const inj = /parameter '[^']+' is vulnerable|is '[^']+' injectable|identified the following injection point|resumed the following injection point/i.test(out);
      const fp = /false positive|unexploitable|looks like.*false/i.test(out);
      const kwGrounded = /parameter 'kw' is vulnerable/i.test(out);
      resolve({ hit: inj && !fp, kwGrounded, out });
    });
  });
}

const main = async () => {
  // sqlmap 可执行性探测（不能把缺失环境记成能力结论）
  const probe = spawnSync(SQLMAP, ['--version'], { encoding: 'utf8', timeout: 30000 });
  if (probe.error) {
    console.log(`[SKIP] sqlmap 不可用（${SQLMAP}）：${probe.error.message}`);
    process.exit(0);
  }

  // 靶场：已在则复用；未起则拉起（同 run.mjs 惯例）
  let labProc = null;
  if (!(await portOpen(PORT))) {
    labProc = spawn(process.execPath, [fileURLToPath(new URL('./lab.mjs', import.meta.url))], {
      cwd: fileURLToPath(new URL('../..', import.meta.url)),
      stdio: 'ignore',
    });
    for (let i = 0; i < 30; i++) { if (await portOpen(PORT)) break; await new Promise((r) => setTimeout(r, 500)); }
  }
  try {
    if (!(await portOpen(PORT))) { console.log('[SKIP] 靶场未能启动'); process.exit(0); }
    const dbProbe = await fetch(`${BASE}/api/items?id=1`).then((r) => r.text()).catch(() => '');
    if (!/Mechanical Keyboard/.test(dbProbe) || /query failed/.test(dbProbe)) {
      console.log('[SKIP] 靶场探针失败（MySQL 未就绪？）');
      process.exit(0);
    }

    // 我方侧：直接复用 run.mjs（它自带 3 轮多数决 + 开关/对照三点判据）
    console.log('[contrast] 我方侧（--param-mine 零告知）…');
    const mine = spawnSync(process.execPath, [fileURLToPath(new URL('./run.mjs', import.meta.url))], { encoding: 'utf8', timeout: 600000 });
    const mineOut = String(mine.stdout || '') + String(mine.stderr || '');
    const mineLine = (mineOut.match(/\[param-mine\] on=(\d+)\/(\d+) off=(\d+) safe=(\d+)/) || []);
    const oursPass = /\[PASS\] 参数挖掘/.test(mineOut);
    const oursFromZero = mineLine[1] ? `${mineLine[1]}/${mineLine[2]}` : 'n/a';
    console.log(`  ${oursPass ? 'HIT' : 'miss'} 我方：on=${oursFromZero} off=${mineLine[3] ?? 'n/a'} safe=${mineLine[4] ?? 'n/a'}`);

    // sqlmap 侧 A：零告知（同 URL，无 kw）
    console.log(`[contrast] sqlmap 零告知 × ${RUNS}…`);
    const zkRuns = [];
    for (let i = 0; i < RUNS; i++) {
      const r = await sqlmapRun(`${BASE}/api/items?id=1`);
      if (r.spawnError) { console.log(`[SKIP] sqlmap 启动失败：${r.spawnError}`); process.exit(0); }
      writeFileSync(`${OUTDIR}zero-knowledge.r${i + 1}.log`, r.out || '');
      const note = (r.out.match(/parameter '[^']+' is vulnerable[^\n]*/) || [''])[0].slice(0, 120);
      zkRuns.push({ hit: r.hit, note });
      console.log(`  ${r.hit ? 'HIT' : 'miss'} zero-knowledge (${i + 1}/${RUNS})`);
    }
    const zkHits = zkRuns.filter((r) => r.hit).length;

    // sqlmap 侧 B：全告知（参数已出现在请求里，等价 -p 全量）——阳性对照
    console.log(`[contrast] sqlmap 全告知 × ${RUNS}…`);
    const fkRuns = [];
    for (let i = 0; i < RUNS; i++) {
      const r = await sqlmapRun(`${BASE}/api/items?id=1&kw=1`);
      if (r.spawnError) { console.log(`[SKIP] sqlmap 启动失败：${r.spawnError}`); process.exit(0); }
      writeFileSync(`${OUTDIR}full-knowledge.r${i + 1}.log`, r.out || '');
      const note = (r.out.match(/parameter '[^']+' is vulnerable[^\n]*/) || [''])[0].slice(0, 120);
      fkRuns.push({ hit: r.hit, note });
      console.log(`  ${r.hit ? 'HIT' : 'miss'} full-knowledge (${i + 1}/${RUNS})`);
    }
    const fkHits = fkRuns.filter((r) => r.hit).length;

    const zk = zkHits > RUNS / 2 ? 'hit' : 'miss';   // 零告知多数决：预期 miss
    const fk = fkHits > RUNS / 2 ? 'hit' : 'miss';   // 全告知多数决：预期 hit
    const expectOk = oursPass && zk === 'miss' && fk === 'hit';
    const summary = {
      at: new Date().toISOString(), runs: RUNS,
      ours: { mode: '--param-mine 零告知', hit: oursPass, fromZero: oursFromZero },
      sqlmapZeroKnowledge: `${zkHits}/${RUNS}（预期 miss：未告知参数无法被发现）`,
      sqlmapFullKnowledge: `${fkHits}/${RUNS}（预期 hit：阳性对照，参数已告知）`,
      verdict: expectOk
        ? '差异在发现环节：我方零告知发现并检出；sqlmap 零告知 0 发现，全告知后可检出 ⇒ 主动挖掘是其没有的能力（不是「更强」的利用能力）'
        : '形态不符预期：见各轮日志，不可作为台账证据',
    };
    mkdirSync(OUTDIR, { recursive: true });
    writeFileSync(RESULTS, JSON.stringify({ summary, logs: { zeroKnowledge: zkRuns, fullKnowledge: fkRuns } }, null, 2), 'utf8');
    console.log(`[contrast] ours=${oursPass ? 'hit' : 'miss'} zero=${zkHits}/${RUNS} full=${fkHits}/${RUNS}`);
    console.log(expectOk ? '[PASS] 参数挖掘同题对照（D102）' : '[FAIL] 参数挖掘同题对照（D102）');
    process.exit(expectOk ? 0 : 1);
  } finally {
    if (labProc) { try { labProc.kill(); } catch { /* 已退出 */ } }
  }
};

main().catch((e) => {
  console.error('[contrast] 运行失败：', e && e.message);
  process.exit(1);
});
