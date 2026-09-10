// ============================================================================
// verify-fix —— 修复后独立复核：布尔点必须命中 boolean，安全点必须零误报
// ============================================================================
import { spawn } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const CLI = fileURLToPath(new URL('../../server/bin/cli.js', import.meta.url));
const CWD = fileURLToPath(new URL('../../server/', import.meta.url));
const LAB = 'http://127.0.0.1:8231';

const CASES = [
  { id: 'C7-boolean', expect: 'hit', url: `${LAB}/shop/blind?id=1`, extra: ['--technique', 'B', '--level', '3', '--risk', '2'] },
  { id: 'C8-time', expect: 'hit', url: `${LAB}/shop/time?id=1`, extra: ['--technique', 'T', '--level', '3', '--risk', '2'] },
  { id: 'A1-int-union', expect: 'hit', url: `${LAB}/shop/item?id=1`, extra: [] },
  { id: 'F18-safe-item', expect: 'clean', url: `${LAB}/safe/item?id=1`, extra: ['--technique', 'B', '--level', '3', '--risk', '2'] },
  { id: 'F19-safe-search', expect: 'clean', url: `${LAB}/safe/search?q=a`, extra: ['--technique', 'B', '--level', '3', '--risk', '2'] },
  { id: 'F20-safe-rand', expect: 'clean', url: `${LAB}/safe/rand?x=1`, extra: ['--technique', 'B', '--level', '3', '--risk', '2'] },
  { id: 'F21-safe-500', expect: 'clean', url: `${LAB}/safe/boom?id=1`, extra: ['--technique', 'B', '--level', '3', '--risk', '2'] },
  { id: 'F22-safe-403', expect: 'clean', url: `${LAB}/safe/blocked?id=1`, extra: ['--technique', 'B', '--level', '3', '--risk', '2'] },
  { id: 'F23-safe-redirect', expect: 'clean', url: `${LAB}/safe/redirect?id=1`, extra: ['--technique', 'B', '--level', '3', '--risk', '2'] },
  { id: 'F24-safe-static', expect: 'clean', url: `${LAB}/safe/static?id=1`, extra: ['--technique', 'B', '--level', '3', '--risk', '2'] },
];

const run = (c) => new Promise((resolve) => {
  const out = fileURLToPath(new URL(`./out/VF-${c.id}.json`, import.meta.url));
  const p = spawn(process.execPath, [CLI, '-u', c.url, ...c.extra, '--timeout', '150000', '-f', 'json', '-o', out],
    { cwd: CWD, env: { ...process.env, NO_PROXY: '127.0.0.1,localhost' }, stdio: ['ignore', 'pipe', 'pipe'] });
  let log = '';
  p.stdout.on('data', d => { log += d; });
  p.stderr.on('data', d => { log += d; });
  const guard = setTimeout(() => { try { p.kill('SIGKILL'); } catch { /* noop */ } }, 200000);
  p.on('close', (code) => {
    clearTimeout(guard);
    let rep = null;
    try { rep = JSON.parse(readFileSync(out, 'utf8')); } catch { /* noop */ }
    resolve({ ...c, code, rep, log: log.slice(-600) });
  });
});

const out = [];
for (const c of CASES) {
  process.stdout.write(`[verify] ${c.id} ... `);
  const r = await run(c);
  const vulns = r.rep?.vulns || [];
  const techs = [...new Set(vulns.map(v => v.technique))].join('+');
  const ok = c.expect === 'hit' ? vulns.length > 0 : vulns.length === 0;
  const boolOk = c.id === 'C7-boolean' ? techs.includes('boolean') : null;
  out.push({ id: c.id, expect: c.expect, vulns: vulns.length, techs, risk: r.rep?.riskLevel || '-', pass: ok && (boolOk === null || boolOk) });
  process.stdout.write(`vulns=${vulns.length} techs=${techs || '-'} ${ok ? 'PASS' : 'FAIL'}\n`);
}
writeFileSync(fileURLToPath(new URL('./verify-fix.json', import.meta.url)), JSON.stringify(out, null, 2));
const fail = out.filter(o => !o.pass);
console.log(`\n复核：${out.length - fail.length}/${out.length} 通过` + (fail.length ? ` | 失败：${fail.map(f => f.id).join('、')}` : ''));
