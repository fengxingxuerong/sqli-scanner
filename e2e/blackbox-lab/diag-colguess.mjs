// 验证列数探测失效的机制：恒 200 + 回显 SQL 时，错误页长度是否仍 >= baseLen*0.5
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

async function probe(pathname) {
  try {
    const r = await fetch(`http://127.0.0.1:${PORT}${pathname}`);
    const body = await r.text();
    return { status: r.status, len: body.length, body };
  } catch (e) {
    return { status: 0, len: 0, body: 'ERR ' + e.message };
  }
}

// A1 点真实 4 列（id/username/email/role）
console.log('=== ORDER BY n 在恒 200 + 回显 SQL 的目标上（A1 点，真实 4 列）===');
const base = await probe('/api/user?id=1');
const baseLen = base.len;
console.log('  基线: status=%s len=%d', base.status, baseLen);
console.log('  判据: 超出列数 ⟺ status>=500 或 len < baseLen*0.5 = %d\n', Math.floor(baseLen * 0.5));

console.log('  n    status  len   len<半基线?  实际应为     工具会判');
for (let n = 1; n <= 7; n++) {
  const r = await probe(`/api/user?id=${encodeURIComponent(`1 ORDER BY ${n}`)}`);
  const shortEnough = r.len < baseLen * 0.5;
  const isOver = n > 4;                        // 真实：>4 列即报错
  const toolSays = (r.status >= 500 || shortEnough) ? '超出' : '成功';
  const correct = (toolSays === (isOver ? '超出' : '成功')) ? '✓' : '✗ 判错';
  console.log('  %s    %s     %s   %s        %s        %s  %s',
    String(n).padEnd(2), String(r.status).padEnd(6), String(r.len).padEnd(5),
    String(shortEnough).padEnd(11), isOver ? '超出' : '成功', toolSays, correct);
}

console.log('\n  错误页样本（ORDER BY 5）:');
const over = await probe('/api/user?id=' + encodeURIComponent('1 ORDER BY 5'));
console.log('   ', over.body.slice(0, 240).replace(/\n/g, ' '));

lab.kill();
console.log('\n靶场已停止');
