// ============================================================================
// sqlmap-bench —— 同一靶场跑 sqlmap 基准，产出「同题对照」检出表
// 口径：--batch --level 1 --risk 1 --flush-session（与 sqli-scanner 默认档对齐）
// ============================================================================
import { spawn } from 'node:child_process';
import { writeFileSync, readFileSync, existsSync } from 'node:fs';

const SQLMAP = 'C:\\Users\\Admin（无密码）\\AppData\\Local\\Programs\\Python\\Python39\\Scripts\\sqlmap.exe';
const LAB = 'http://127.0.0.1:8231';
const OUTDIR = 'D:\\projects\\sqli-scanner\\e2e\\redteam-lab\\sqlmap-out';

const CASES = [
  { id: 'A1-int-union', args: ['-u', `${LAB}/shop/item?id=1`] },
  { id: 'A2-str-union', args: ['-u', `${LAB}/shop/search?name=alice`] },
  { id: 'A3-like', args: ['-u', `${LAB}/shop/find?q=a`] },
  { id: 'A4-orderby', args: ['-u', `${LAB}/shop/sort?by=id`] },
  { id: 'A5-dual-param', args: ['-u', `${LAB}/shop/detail?id=1&cat=0`] },
  { id: 'B6-error', args: ['-u', `${LAB}/shop/err?id=1`] },
  { id: 'C7-boolean', args: ['-u', `${LAB}/shop/blind?id=1`] },
  { id: 'C8-time', args: ['-u', `${LAB}/shop/time?id=1`, '--technique=T'] },
  { id: 'D9-post-form', args: ['-r', 'D:\\projects\\sqli-scanner\\e2e\\redteam-lab\\reqs\\login.txt'] },
  { id: 'D10-json', args: ['-r', 'D:\\projects\\sqli-scanner\\e2e\\redteam-lab\\reqs\\json.txt'] },
  { id: 'D12-xff-header', args: ['-r', 'D:\\projects\\sqli-scanner\\e2e\\redteam-lab\\reqs\\xff.txt', '--level=3'] },
  { id: 'D13-path', args: ['-u', `${LAB}/shop/user/1*`] },
  { id: 'E16-stacked', args: ['-u', `${LAB}/shop/stack?id=1`] },
  { id: 'E17-waf-guarded', args: ['-u', `${LAB}/waf/item?id=1`] },
  { id: 'F18-safe-item', args: ['-u', `${LAB}/safe/item?id=1`] },
  { id: 'F20-safe-rand', args: ['-u', `${LAB}/safe/rand?x=1`] },
  { id: 'F21-safe-500', args: ['-u', `${LAB}/safe/boom?id=1`] },
  { id: 'F22-safe-403', args: ['-u', `${LAB}/safe/blocked?id=1`] },
];

const run = (c) => new Promise((resolve) => {
  const args = [...c.args, '--batch', '--flush-session', '-v', '0', '--ignore-proxy',
    '--output-dir', OUTDIR, '--answers=follow=Y'];
  const t0 = Date.now();
  // 清除环境代理：sqlmap 会读 *_PROXY 且 --ignore-proxy 与之互斥，直接清空最稳
  const env = { ...process.env };
  for (const k of Object.keys(env)) if (/^(http|https|all)_proxy$/i.test(k)) delete env[k];
  const p = spawn(SQLMAP, args, { env, stdio: ['ignore', 'pipe', 'pipe'] });
  let out = '';
  p.stdout.on('data', d => { out += d; });
  p.stderr.on('data', d => { out += d; });
  const guard = setTimeout(() => { try { p.kill('SIGKILL'); } catch { /* noop */ } }, 240000);
  p.on('close', () => {
    clearTimeout(guard);
    resolve({ id: c.id, ms: Date.now() - t0, out });
  });
});

const only = process.argv[2] ? process.argv[2].split(',') : null;
const results = only ? (JSON.parse(readFileSync(new URL('./results-sqlmap.json', import.meta.url), 'utf8'))).filter(r => !only.includes(r.id)) : [];
for (const c of CASES.filter(c => !only || only.includes(c.id))) {
  process.stdout.write(`[sqlmap] ${c.id} ... `);
  const r = await run(c);
  const inj = /is vulnerable|parameter '[^']*' is vulnerable|injectable/i.test(r.out);
  const fp = /false positive|unexploitable|looks like.*false/i.test(r.out);
  writeFileSync(`${OUTDIR}\\${c.id}.log`, r.out);
  results.push({ id: c.id, hit: inj && !fp, ms: r.ms, note: (r.out.match(/parameter '[^']+' is vulnerable[^\n]*/i) || r.out.match(/sqlmap identified the following injection point[^\n]*/i) || [''])[0].slice(0, 140) });
  process.stdout.write(`${inj ? 'HIT' : 'miss'} ${r.ms}ms\n`);
}
writeFileSync('D:\\projects\\sqli-scanner\\e2e\\redteam-lab\\results-sqlmap.json', JSON.stringify(results, null, 2));
console.log(`sqlmap done: ${results.filter(r => r.hit).length}/${results.length}`);
