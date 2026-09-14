// ============================================================================
// e2e/run-all.mjs —— e2e 靶场统一入口
//
// 背景：e2e/ 下有 15+ 个靶场目录，各自有入口脚本、端口与外部依赖（MySQL/PG/MariaDB/Java），
// 想跑一轮回归得逐个记命令、逐个判断环境是否满足。本入口做两件事：
//   ① `--list`：列出全部靶场 + 依赖 + **当前环境是否满足**（端口探测）
//   ② 默认只跑「依赖满足」的靶场，避免"跑一半全挂在缺环境上"的噪音；
//      `--only a,b` 显式指定，`--all` 强制全跑（缺依赖的会失败，但会如实汇总）
//
// 用法：
//   node e2e/run-all.mjs --list
//   node e2e/run-all.mjs                      # 跑依赖满足的全部
//   node e2e/run-all.mjs --only multi-engine-lab,redteam-lab
//   node e2e/run-all.mjs --all
// ============================================================================
import { spawn } from 'node:child_process';
import net from 'node:net';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '..');

// 靶场清单。deps 里的键对应 probe 表；env 为该靶场专有环境变量。
const LABS = [
  { name: 'redteam-lab', desc: '红队评测：24 靶点（17 注入 + 7 安全对照）', entry: 'e2e/redteam-lab/run-with-env.mjs', args: ['r2'], deps: ['mysql'] },
  { name: 'retest-lab', desc: '单点重测接口端到端（自起靶场）', entry: 'e2e/retest-lab/verify.mjs', deps: [] },
  { name: 'multi-engine-lab', desc: '多引擎 tamper A/B（真 JDBC：H2/HSQLDB/Derby）', entry: 'e2e/multi-engine-lab/verify.mjs', deps: ['java'], env: { ENGINE_JARS: 'D:\\engines\\jars\\h2.jar;D:\\engines\\jars\\hsqldb.jar;D:\\engines\\jars\\derby.jar;D:\\engines\\jars\\derbyshared.jar' } },
  { name: 'tamper-matrix', desc: 'tamper × WAF 规则绕过矩阵', entry: 'e2e/tamper-matrix/tamper-test.mjs', deps: [] },
  { name: 'real-world-lab', desc: '拟真靶场（登录/搜索/上传，PGlite 内置）', entry: 'e2e/real-world-lab/verify.mjs', deps: [] },
  { name: 'real-mysql-lab', desc: '真实 MySQL 驱动靶场验证', entry: 'e2e/real-mysql-lab/verify.mjs', deps: ['mysql'] },
  { name: 'pentest-lab', desc: '渗透视角刁钻场景实测', entry: 'e2e/pentest-lab/verify.mjs', deps: ['mysql'] },
  { name: 'waf-real', desc: '真实 CRS v4.1.0 规则绕过验证', entry: 'e2e/waf-real/selftest.mjs', deps: ['mysql'] },
  { name: 'oob-real-lab', desc: 'OOB 带外全链路（PG COPY TO PROGRAM / MySQL UNC）', entry: 'e2e/oob-real-lab/verify.mjs', deps: ['pg', 'mysql'] },
  { name: 'pg-osshell', desc: 'PG os-shell 真机闭环（COPY FROM PROGRAM 落表 → 回显）', entry: 'e2e/oob-real-lab/pg-osshell.e2e.mjs', deps: ['pg'] },
  { name: 'recall-lab', desc: '假阳性验证（安全靶场零误报）', entry: 'e2e/recall-lab/false-positive.e2e.js', deps: [] },
  { name: 'detection-runner', desc: '数据驱动检测测试', entry: 'e2e/detection-runner/run.js', deps: [] },
  { name: 'udf-lab', desc: 'UDF 接管真实验证（真 DLL）', entry: 'e2e/udf-lab/udf-takeover.e2e.mjs', deps: ['mysql'] },
  { name: 'waf-lab', desc: 'WAF 规则对比实验', entry: 'e2e/waf-lab/compare.e2e.js', deps: [] },
];

const PROBES = {
  mysql: { port: 3306, label: 'MySQL:3306' },
  mariadb: { port: 3308, label: 'MariaDB:3308' },
  pg: { port: 5432, label: 'PostgreSQL:5432' },
  java: { label: 'Java' },
};

const probePort = (port, timeout = 800) =>
  new Promise((resolve) => {
    const s = net.connect(port, '127.0.0.1');
    const done = (v) => { try { s.destroy(); } catch { /* noop */ } resolve(v); };
    s.on('connect', () => done(true));
    s.on('error', () => done(false));
    setTimeout(() => done(false), timeout);
  });

const hasJava = () =>
  new Promise((resolve) => {
    const p = spawn('java', ['-version'], { stdio: 'ignore' });
    p.on('error', () => resolve(false));
    p.on('exit', (c) => resolve(c === 0));
    setTimeout(() => { try { p.kill(); } catch { /* noop */ } resolve(false); }, 3000);
  });

async function depStatus(lab) {
  const missing = [];
  for (const d of lab.deps) {
    if (d === 'java') {
      if (!(await hasJava())) missing.push(PROBES.java.label);
    } else {
      const pr = PROBES[d];
      if (!(await probePort(pr.port))) missing.push(pr.label);
    }
  }
  return missing;
}

const runOne = (lab) =>
  new Promise((resolve) => {
    const t0 = Date.now();
    const p = spawn('node', [lab.entry, ...(lab.args || [])], {
      cwd: ROOT,
      env: { ...process.env, NO_PROXY: '127.0.0.1,localhost', ...(lab.env || {}) },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let out = '';
    p.stdout.on('data', (d) => { out += d; });
    p.stderr.on('data', (d) => { out += d; });
    p.on('exit', (code) => {
      // 从输出里抓一眼关键字（各靶场格式不一，仅作提示，不作判定）
      const hint = out.split('\n').filter((l) => /done:|结论|误报|✅|❌|FAIL|PASS/i.test(l)).slice(-2).join(' | ').slice(0, 160);
      resolve({ code, ms: Date.now() - t0, hint, tail: out.split('\n').filter(Boolean).slice(-3).join('\n') });
    });
  });

const argv = process.argv.slice(2);
const listMode = argv.includes('--list');
const allMode = argv.includes('--all');
const onlyIdx = argv.indexOf('--only');
const only = onlyIdx >= 0 ? (argv[onlyIdx + 1] || '').split(',').map((s) => s.trim()).filter(Boolean) : null;

console.log('=== e2e 靶场清单（依赖探测）===');
const status = [];
for (const lab of LABS) {
  const missing = await depStatus(lab);
  status.push({ lab, missing, ok: missing.length === 0 });
  const mark = missing.length ? '⛔' : '✅';
  console.log(`${mark} ${lab.name.padEnd(20)} ${lab.desc}`);
  if (missing.length) console.log(`   └ 缺依赖: ${missing.join(', ')}`);
}
console.log('');

if (listMode) process.exit(0);

let targets = status;
if (only) targets = status.filter((s) => only.includes(s.lab.name));
else if (!allMode) targets = status.filter((s) => s.ok);

if (!targets.length) {
  console.log('没有可跑的靶场：指定 --only 或 --all（注意缺依赖的会失败）');
  process.exit(0);
}

console.log(`=== 开始运行 ${targets.length} 个靶场 ===`);
const results = [];
for (const t of targets) {
  process.stdout.write(`▶ ${t.lab.name} ... `);
  if (!t.ok) console.log(`(缺依赖: ${t.missing.join(', ')})`);
  const r = await runOne(t.lab);
  results.push({ name: t.lab.name, ...r });
  console.log(`${r.code === 0 ? '✅ 通过' : '❌ 失败(code=' + r.code + ')'}  ${(r.ms / 1000).toFixed(1)}s  ${r.hint}`);
}

console.log('');
console.log('=== 汇总 ===');
for (const r of results) {
  console.log(`${r.code === 0 ? '✅' : '❌'} ${r.name.padEnd(20)} ${(r.ms / 1000).toFixed(1)}s`);
}
const failed = results.filter((r) => r.code !== 0);
console.log('');
console.log(failed.length ? `❌ ${failed.length}/${results.length} 个靶场失败` : `✅ 全部 ${results.length} 个靶场通过`);
process.exit(failed.length ? 1 : 0);
