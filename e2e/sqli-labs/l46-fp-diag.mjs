// [todo#39] L46 报错回显与 dbmsFromError 误判复现（v2：先等靶场起来再发探针）
import { spawn } from 'node:child_process';
import { setTimeout as sleep } from 'node:timers/promises';
import { dbmsFromError, ERROR_SIG_BY_DBMS } from '../../server/src/engine/payloads/index.js';

const PORT = 8130;
const BASE = `http://127.0.0.1:${PORT}`;

const lab = spawn('python', ['e2e/sqli-labs/sqli-labs.py'], { stdio: 'ignore' });
let up = false;
for (let i = 0; i < 40 && !up; i++) {
  try { await fetch(`${BASE}/Less-1/?id=1`); up = true; } catch { await sleep(300); }
}
if (!up) { console.error('lab not up'); lab.kill(); process.exit(1); }

const probes = [
  ['单引号', "id'"],
  ['AND子句', 'id AND 1=1-- -'],
  ['SLEEP', 'id AND SLEEP(1)-- -'],
  ['引号破坏', "id' AND '1'='1"],
];
for (const [name, v] of probes) {
  const r = await fetch(`${BASE}/Less-46/?sort=${encodeURIComponent(v)}`);
  const body = await r.text();
  const inferred = dbmsFromError(body);
  console.log(`[${name}] status=${r.status} len=${body.length} dbmsFromError=${inferred}`);
  const m = body.match(/<pre>([\s\S]*?)<\/pre>/);
  if (m) console.log('  err:', m[1].slice(0, 150).replace(/\n/g, ' '));
}

// 对单引号探针响应逐条签名定位命中来源
const r2 = await fetch(`${BASE}/Less-46/?sort=${encodeURIComponent("id'")}`);
const body2 = await r2.text();
let s = body2.replace(/<script[\s\S]*?<\/script>/gi, ' ').replace(/<style[\s\S]*?<\/style>/gi, ' ').replace(/<!--[\s\S]*?-->/g, ' ').replace(/<[^>]*>/g, ' ');
console.log('--- 签名逐条命中（剥标签后文本）---');
for (const { dbms, sig } of ERROR_SIG_BY_DBMS) {
  const m = sig.exec(s);
  if (m) console.log(`命中: ${dbms} match=${JSON.stringify(m[0])} @${m.index} 上下文: ...${s.slice(Math.max(0, m.index - 80), m.index + 80).replace(/\n/g, ' ')}...`);
}
console.log('--- 剥标签后前 400 字 ---');
console.log(s.replace(/\s+/g, ' ').slice(0, 400));

lab.kill();
process.exit(0);
