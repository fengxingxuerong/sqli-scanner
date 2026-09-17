// 独立诊断：L2 探针在真实 MySQL 上到底发生了什么（不改被测代码）
import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '../..');
const PORT = 8099;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function startLab() {
  const proc = spawn('node', [path.join(HERE, 'lab-app.mjs')], {
    cwd: ROOT, env: { ...process.env, LAB_PORT: String(PORT) }, stdio: 'ignore',
  });
  for (let i = 0; i < 40; i++) {
    try { const r = await fetch(`http://127.0.0.1:${PORT}/__lab/health`); if (r.ok) return proc; } catch {}
    await sleep(250);
  }
  proc.kill(); throw new Error('靶场未就绪');
}

const lab = await startLab();
const MARK = '__SQ__';

// A1 点是 4 列（id/username/email/role），回显第 1 列。
// 复刻 L2 的两种探针形态，观察响应差异。
const CASES = [
  ['基线（第2列 NULL）', `1 UNION SELECT '${MARK}',NULL,NULL,NULL-- -`],
  ['SQLite 探针', `1 UNION SELECT '${MARK}',sqlite_version(),NULL,NULL-- -`],
  ['MySQL 探针(@@version_comment)', `1 UNION SELECT '${MARK}',@@version_comment,NULL,NULL-- -`],
  ['PG 探针', `1 UNION SELECT '${MARK}',current_setting('server_version'),NULL,NULL-- -`],
  ['H2 探针', `1 UNION SELECT '${MARK}',H2VERSION(),NULL,NULL-- -`],
];

function stripEcho(raw, payload) {
  let t = String(raw || '');
  t = t.replace(/&#(\d+);/g, (_, d) => String.fromCharCode(Number(d) || 0))
    .replace(/&#x([0-9a-fA-F]+);/g, (_, h) => String.fromCharCode(parseInt(h, 16) || 0))
    .replace(/&lt;/g, '<').replace(/&gt;/g, '>')
    .replace(/&quot;/g, String.fromCharCode(34)).replace(/&apos;/g, String.fromCharCode(39))
    .replace(/&amp;/g, '&');
  for (let i = 0; i < 2; i++) {
    try { const d = decodeURIComponent(t.replace(/\+/g, ' ')); if (d !== t) t = d; else break; } catch { break; }
  }
  const variants = new Set([payload]);
  try { variants.add(encodeURIComponent(payload)); } catch {}
  for (const v of variants) if (v && v.length > 3) t = t.split(v).join('');
  return t;
}

console.log('=== L2 探针实测（/api/user，4 列，回显第 1 列）===');
for (const [tag, payload] of CASES) {
  const url = `http://127.0.0.1:${PORT}/api/user?id=${encodeURIComponent(payload)}`;
  let body = '';
  let status = 0;
  try { const r = await fetch(url); status = r.status; body = await r.text(); } catch (e) { body = 'ERR ' + e.message; }
  const cleaned = stripEcho(stripEcho(body, payload), payload);
  const hasRaw = body.includes(MARK);
  const hasClean = cleaned.includes(MARK);
  console.log('\n  %s', tag);
  console.log('    status=%s  原始含标记=%s  剔除回显后含标记=%s  %s',
    status, hasRaw, hasClean, hasClean ? '← 判定为「可执行」' : '← 判定为「不可执行」');
  const idx = cleaned.indexOf(MARK);
  if (idx >= 0) console.log('    标记后 120 字: %j', cleaned.slice(idx, idx + 120).replace(/\n/g, ' '));
  else console.log('    原始响应片段: %j', body.slice(0, 180).replace(/\n/g, ' '));
}

lab.kill();
console.log('\n靶场已停止');
