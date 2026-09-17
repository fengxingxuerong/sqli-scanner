// ============================================================================
// blackbox-lab / dump-verify.mjs —— 提取链完整性验证（M3）
//
// 为什么这是最高价值的一项：
//   `--dbs / --tables / --columns / --dump` 是 sqlmap 的核心功能，而本项目**从未验证**过
//   「拖出来的数据和库里是否一字不差」。检出率再高，拖错一个字段就是交付事故。
//
// 方法（三段）：
//   ① 真值：用 mysql 客户端直连靶场库，导出 users/products 的完整数据
//   ② 提取：调工具 `--dump` 走 HTTP 注入点拖同样的数据
//   ③ 比对：逐行逐字段比，不一致就打印差异位置
//
// 用法：node e2e/blackbox-lab/dump-verify.mjs
// ============================================================================

import { spawn, execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '../..');
const PORT = 8099;
const BASE = `http://127.0.0.1:${PORT}`;
const OUT = path.join(HERE, 'out');
fs.mkdirSync(OUT, { recursive: true });

const MYSQL = 'D:/mysql/bin/mysql.exe';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function mysqlQuery(sql) {
  const out = execFileSync(MYSQL, [
    '-h', '127.0.0.1', '-P', '3306', '-uroot', '-proot',
    '-N', '-B', '-e', `USE blackbox_lab; ${sql}`,
  ], { encoding: 'utf8', timeout: 30000, maxBuffer: 32 * 1024 * 1024 });
  return out.split('\n').filter((l) => l.length).map((l) => l.split('\t'));
}

async function startLab() {
  const proc = spawn('node', [path.join(HERE, 'lab-app.mjs')], {
    cwd: ROOT, env: { ...process.env, LAB_PORT: String(PORT) }, stdio: 'ignore',
  });
  for (let i = 0; i < 40; i++) {
    try { const r = await fetch(`${BASE}/__lab/health`); if (r.ok) return proc; } catch {}
    await sleep(250);
  }
  proc.kill(); throw new Error('靶场未就绪');
}

function runCli(args, outFile) {
  return new Promise((resolve) => {
    const p = spawn('node', ['server/bin/cli.js', ...args, '--format', 'json', '-o', outFile], {
      cwd: ROOT, stdio: ['ignore', 'pipe', 'pipe'],
      env: { ...process.env, MYSQL_PORT: '3306', MYSQL_USER: 'root', MYSQL_PASSWORD: 'root' },
    });
    let out = '';
    p.stdout.on('data', (d) => { out += d; });
    p.stderr.on('data', (d) => { out += d; });
    const t = setTimeout(() => { try { p.kill(); } catch { /* noop */ } }, 420000);
    p.on('exit', (code) => { clearTimeout(t); resolve({ code, out }); });
  });
}

function readJson(f) {
  try { return JSON.parse(fs.readFileSync(f, 'utf8')); } catch { return null; }
}

// ── ① 真值 ──────────────────────────────────────────────────────────────────
console.log('=== ① 真值（直接读库）===');
const truth = {};
for (const t of ['users', 'products']) {
  const rows = mysqlQuery(`SELECT * FROM ${t} ORDER BY 1`);
  truth[t] = rows;
  console.log('  %s: %d 行 × %d 列', t, rows.length, rows[0] ? rows[0].length : 0);
}

const lab = await startLab();
console.log('  靶场已起 @', BASE);

// A2 是字符串型回显点（/api/search?name=）—— 有回显才能走 UNION 提取
const TARGET = `${BASE}/api/search?name=alice`;

// ── ② 提取 ──────────────────────────────────────────────────────────────────
console.log('\n=== ② 工具提取（--dump）===');
const outFile = path.join(OUT, 'dump-users.json');
if (fs.existsSync(outFile)) fs.unlinkSync(outFile);
const r = await runCli(['-u', TARGET, '--dump', '-D', 'blackbox_lab', '-T', 'users'], outFile);
console.log('  CLI 退出码 %s | 报告存在: %s', r.code, fs.existsSync(outFile));

const rep = fs.existsSync(outFile) ? readJson(outFile) : null;

// ── ③ 比对 ──────────────────────────────────────────────────────────────────
console.log('\n=== ③ 逐字比对 ===');
if (!rep) {
  console.log('  ✗ 报告未生成 —— 提取链**完全未产出**');
  console.log('  工具输出尾部:');
  for (const l of r.out.split('\n').slice(-14)) if (l.trim()) console.log('   ', l.slice(0, 140));
} else {
  const data = rep.data || {};
  const got = (data.rows && (data.rows.users || data.rows)) || null;
  console.log('  报告 dbms=%j  riskLevel=%j', rep.dbms, rep.riskLevel);
  console.log('  data 键: %j', Object.keys(data));
  console.log('  data.rows 类型: %s', Array.isArray(got) ? `数组(${got.length})` : typeof got);
  const dbs = data.databases || [];
  console.log('  data.databases: %j', Array.isArray(dbs) ? dbs : dbs);

  if (Array.isArray(got) && got.length) {
    const t = truth.users;
    console.log('\n  真值 %d 行 vs 提取 %d 行', t.length, got.length);
    let diff = 0;
    const n = Math.min(t.length, got.length);
    for (let i = 0; i < n; i++) {
      const a = t[i].join('|');
      const row = got[i];
      const b = Array.isArray(row) ? row.join('|') : Object.values(row || {}).join('|');
      if (a !== b) {
        diff += 1;
        if (diff <= 3) {
          console.log('    行 %d 不一致:', i + 1);
          console.log('      真值: %j', a.slice(0, 160));
          console.log('      提取: %j', b.slice(0, 160));
        }
      }
    }
    console.log('\n  结果: %s（%d/%d 行不一致）',
      diff === 0 && t.length === got.length ? '✓ 逐字一致' : '✗ 有差异', diff, n);
  } else {
    console.log('  ✗ 报告里没有可用的行数据 —— 提取链未产出数据');
    const tail = r.out.split('\n').filter((l) => /未|无法|失败|skip|SKIP|error/i.test(l)).slice(-8);
    for (const l of tail) console.log('   ', l.slice(0, 140));
  }
}

lab.kill();
console.log('\n靶场已停止');
