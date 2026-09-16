// P1 根因验证：DB2 用常量串 'DB2' 做指纹，MySQL 能否原样返回它？
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

// 模拟 DB_FINGERPRINTER 版本函数通道对 DB2 的探测：
//   payload = `${orig} UNION SELECT <WRAP[DB2]("'DB2'")>,NULL,...-- -`
// 靶场 A1 点是 4 列（id/username/email/role），回显第 1 列。
const candidates = [
  "1 UNION SELECT 'DB2',NULL,NULL,NULL-- -",
  "1 UNION SELECT CONCAT('__S__','DB2','__E__'),NULL,NULL,NULL-- -",
  // 对照：MySQL 真实版本函数（sig 需要能匹配纯版本号）
  "1 UNION SELECT CONCAT('__S__',VERSION(),'__E__'),NULL,NULL,NULL-- -",
  "1 UNION SELECT CONCAT('__S__',@@version_comment,'__E__'),NULL,NULL,NULL-- -",
];

console.log('=== DB2 常量指纹在真实 MySQL 上的表现 ===');
for (const p of candidates) {
  const url = `http://127.0.0.1:${PORT}/api/user?id=${encodeURIComponent(p)}`;
  let body = '';
  try { const r = await fetch(url); body = await r.text(); } catch (e) { body = 'ERR ' + e.message; }
  const m = body.match(/__S__(.*?)__E__/is);
  const ver = m ? m[1] : (body.includes('DB2') ? 'DB2(裸串)' : '');
  console.log('\n  payload: %s', p);
  console.log('    → 从响应提取到标记值: %j', ver);
  console.log('    → 若走 DB_VERSION 通道，DB2 的 sig=/DB2/i 是否命中: %s',
    /DB2/i.test(ver) ? '**命中（会误判为 DB2）**' : '不命中');
  console.log('    → MySQL 的 sig 是否命中: %s',
    /mysql_fetch|mysqli|You have an error in your SQL syntax|XPATH syntax|SQL syntax/i.test(ver) ? '命中' : '**不命中（无法定库）**');
}

lab.kill();
console.log('\n靶场已停止');
