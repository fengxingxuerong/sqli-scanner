// P1 诊断：拿靶场真实响应喂 dbmsFromError，看 DB2 从哪个签名来。
// 用法：node e2e/blackbox-lab/diag-dbms.mjs
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
  proc.kill();
  throw new Error('靶场未就绪');
}

const lab = await startLab();
const { dbmsFromError, ERROR_SIG_BY_DBMS } = await import('../../server/src/engine/payloads.js');

console.log('=== ERROR_SIG_BY_DBMS 顺序（dbmsFromError 按此顺序返回首个命中）===');
for (const { dbms, sig } of ERROR_SIG_BY_DBMS) {
  console.log('  %s → %s', dbms.padEnd(12), String(sig).slice(0, 90));
}

// 抓各靶点的真实响应（含注入后）
const CASES = [
  ['A1 基线', '/api/user?id=1'],
  ['A1 单引号', "/api/user?id=1'"],
  ['A1 注入 extractvalue', "/api/user?id=1%20AND%20extractvalue(1,concat(0x7e,version()))"],
  ['A2 基线', '/api/search?name=alice'],
  ['B1 基线', '/api/product?id=1'],
  ['F3 恒500', '/api/safe/error'],
];

console.log('\n=== 逐响应调用 dbmsFromError ===');
for (const [tag, p] of CASES) {
  let status = 0;
  let body = '';
  try {
    const r = await fetch('http://127.0.0.1:' + PORT + p);
    status = r.status;
    body = await r.text();
  } catch (e) {
    body = 'ERR ' + e.message;
  }
  const hit = dbmsFromError(body);
  // 找出具体是哪个签名匹配
  let which = null;
  for (const { dbms, sig } of ERROR_SIG_BY_DBMS) {
    if (new RegExp(sig.source === undefined ? sig : sig.source, sig.flags || 'i').test(body)) {
      which = dbms;
      break;
    }
  }
  console.log('  %s  status=%s dbmsFromError=%j  首个命中签名=%s',
    tag.padEnd(22), status, hit, which);
  console.log('      body 片段: %j', body.slice(0, 160));
}

lab.kill();
console.log('\n靶场已停止');
