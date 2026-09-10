// ============================================================================
// run-scan —— 用 sqli-scanner CLI 逐个打靶，采集实战指标
//   Round1：默认配置（level 1 / 默认技术集）——「开箱即用」口径
//   Round2：实战配置（level 3 / risk 2 / 全技术 BEUSTQ）——「老师傅调参」口径
// 指标：是否命中、命中技术位、DBMS 指纹、耗时、请求数
// ============================================================================
import { spawn } from 'node:child_process';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const LAB = process.env.LAB || 'http://127.0.0.1:8231';
const CLI = fileURLToPath(new URL('../../server/bin/cli.js', import.meta.url));
const OUT = fileURLToPath(new URL('./out/', import.meta.url));
mkdirSync(OUT, { recursive: true });

const BASE_TECH = 'BEUSTQ'; // boolean error union stacked time query(inline)
const T = (id, url, extra = []) => ({ id, url, extra });

const TARGETS = [
  T('A1-int-union', `${LAB}/shop/item?id=1`),
  T('A2-str-union', `${LAB}/shop/search?name=alice`),
  T('A3-like', `${LAB}/shop/find?q=a`),
  T('A4-orderby', `${LAB}/shop/sort?by=id`),
  T('A5-dual-param', `${LAB}/shop/detail?id=1&cat=0`),
  T('B6-error', `${LAB}/shop/err?id=1`),
  T('C7-boolean', `${LAB}/shop/blind?id=1`),
  T('C8-time', `${LAB}/shop/time?id=1`),
  T('D9-post-form', `${LAB}/login`, ['--method', 'POST', '--body', '{"username":"alice","password":"x"}']),
  T('D10-json', `${LAB}/api/profile`, ['--method', 'POST', '--body', '{"uid":1}']),
  T('D11-cookie', `${LAB}/shop/cookie`, ['--header', 'cookie: uid=1', '--test-headers']),
  T('D12-xff-header', `${LAB}/shop/ip`, ['--header', 'x-forwarded-for: 1', '--test-headers']),
  T('D13-path', `${LAB}/shop/user/1`, ['--test-path']),
  // 用真实 base64 值（MQ== = '1'）：短值 MQ 长度 <4 不会触发编码识别，回归会覆盖不到该路径
  T('D14-base64', `${LAB}/shop/b64?id=MQ==`),
  // 自定义参数分隔符（; ）：必须配 --param-del 才会正确切分 query
  T('D15-param-del', `${LAB}/shop/semi?a=1;id=1`, ['--param-del', ';']),
  // 每次用唯一会话 id：靶场把写入值存在内存 store[sid]，复用同一 sid 会让"基线触发页"
  // 读到上一轮残留探针 → 基线自带报错 → 走基线噪声路径 → 判定条件不成立（实测踩过）。
  T('E15-second-order', `${LAB}/account/update`, ['--method', 'POST', '--body', '{"name":"alice"}',
    '--header', `cookie: sid=rt${Date.now().toString(36)}`, '--test-headers',
    '--second-order', `${LAB}/account/me`, '--allow-second-order-writes', '--no-production-mode']),
  T('E16-stacked', `${LAB}/shop/stack?id=1`),
  T('E17-waf-guarded', `${LAB}/waf/item?id=1`),
  T('F18-safe-item', `${LAB}/safe/item?id=1`),
  T('F19-safe-search', `${LAB}/safe/search?q=a`),
  T('F20-safe-rand', `${LAB}/safe/rand?x=1`),
  T('F21-safe-500', `${LAB}/safe/boom?id=1`),
  T('F22-safe-403', `${LAB}/safe/blocked?id=1`),
  T('F23-safe-redirect', `${LAB}/safe/redirect?id=1`),
  T('F24-safe-static', `${LAB}/safe/static?id=1`),
];

const runOnce = (id, url, extra, round) => new Promise((resolve) => {
  const outFile = fileURLToPath(new URL(`./out/${id}.${round}.json`, import.meta.url));
  const args = [CLI, '-u', url, ...extra, '--timeout', '150000', '-f', 'json', '-o', outFile];
  const t0 = Date.now();
  const p = spawn(process.execPath, args, {
    cwd: fileURLToPath(new URL('../../server/', import.meta.url)),
    env: { ...process.env, NO_PROXY: '127.0.0.1,localhost', no_proxy: '127.0.0.1,localhost' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let log = '';
  p.stdout.on('data', d => { log += d; });
  p.stderr.on('data', d => { log += d; });
  const guard = setTimeout(() => { try { p.kill('SIGKILL'); } catch { /* noop */ } }, 200000);
  p.on('close', (code) => {
    clearTimeout(guard);
    const ms = Date.now() - t0;
    let rep = null;
    try { rep = JSON.parse(readFileSync(outFile, 'utf8')); } catch { /* 无报告 */ }
    resolve({ id, round, code, ms, log: log.slice(-1500), report: rep });
  });
});

const brief = (r) => {
  if (!r.report) return { hit: false, techs: '', dbms: '', risk: '', reqs: 0, verdict: '', err: (r.log.match(/失败|Error|error/g) || [''])[0] };
  const rep = r.report;
  const vulns = rep.vulns || [];
  return {
    hit: vulns.length > 0,
    techs: [...new Set(vulns.map(v => v.technique))].join('+'),
    dbms: rep.dbms || (rep.summary?.dbmsEvidence?.dbms) || '',
    risk: rep.riskLevel || '',
    reqs: rep.summary?.validity?.counts?.total ?? 0,
    verdict: rep.summary?.verdict || '',
    err: '',
  };
};

const round = process.argv[2] || 'r1';
const only = process.argv[3] ? process.argv[3].split(',') : null;
const list = only ? TARGETS.filter(t => only.includes(t.id)) : TARGETS;

const results = [];
for (const t of list) {
  const extra = [...t.extra];
  if (round === 'r2') extra.push('--level', '3', '--risk', '2', '--technique', BASE_TECH);
  process.stdout.write(`[${round}] ${t.id} ... `);
  const r = await runOnce(t.id, t.url, extra, round);
  const b = brief(r);
  results.push({ id: t.id, url: t.url, round, exit: r.code, ms: r.ms, ...b, raw: r.report || null });
  process.stdout.write(`${b.hit ? 'HIT' : 'miss'} ${b.techs} ${b.ms}ms req=${b.reqs}\n`);
}
writeFileSync(new URL(`./results-${round}.json`, import.meta.url), JSON.stringify(results, null, 2));
console.log(`\n${round} done: ${results.filter(r => r.hit).length}/${results.length} hit`);
