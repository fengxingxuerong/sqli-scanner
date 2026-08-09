// tamper 绕过 WAF 演示
// 本地模式：起带关键词 WAF 的本地靶机，统计绕过率（零风险，无外部依赖）。
// 远程模式：--url <remote> 对真实目标联调，须 --authorized 显式确认授权（否则拒绝运行）。
//
// 运行：
//   本地：node server/scripts/tamperBypassDemo.mjs
//   远程：node server/scripts/tamperBypassDemo.mjs --url "http://target/vuln.php" --authorized
//         （remote 传页面 URL，不含已有 q= 参数；脚本自动拼接）
import http from 'node:http';
import { URL } from 'node:url';
import { tamperRegistry } from '../src/core/tamper/TamperRegistry.js';
// 副作用：触发内置插件注册（applyTampers.js 内部 registerMany）
import '../src/core/tamper/applyTampers.js';

// —— 本地靶机 WAF 规则（与 server/tests/tamper.test.js 一致）——
function wafBlocks(sql) {
  return /union\s+select/i.test(sql) || /and\s+1=1/i.test(sql);
}

const localServer = http.createServer((req, res) => {
  const u = new URL(req.url, 'http://localhost');
  const q = u.searchParams.get('q') || '';
  if (wafBlocks(q)) {
    res.writeHead(403, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('BLOCKED by WAF');
    return;
  }
  res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
  res.end('OK page');
});

function getStatus(url) {
  return new Promise((resolve) => {
    const r = http.get(url, (res) => {
      res.resume();
      resolve(res.statusCode || 0);
    });
    r.on('error', () => resolve(0));
    r.setTimeout(3000, () => {
      r.destroy();
      resolve(0);
    });
  });
}

// 拼接 base + q 参数（兼容 base 已含 ? 或无 ?）
function buildUrl(base, q) {
  const sep = base.includes('?') ? '&' : '?';
  return `${base}${sep}q=${encodeURIComponent(q)}`;
}

const PAYLOADS = ['UNION SELECT flag FROM secrets', '1 AND 1=1', 'normal search'];
const TAMPER_SETS = [
  { name: '原始(无 tamper)', plugins: [] },
  { name: 'space2comment', plugins: ['space2comment'] },
  { name: 'space2comment+lowercase', plugins: ['space2comment', 'lowercase'] },
  { name: 'randomcase', plugins: ['randomcase'] },
];

async function evaluate(base) {
  const rows = [];
  for (const ts of TAMPER_SETS) {
    let bypass = 0;
    const detail = [];
    for (const p of PAYLOADS) {
      const out = tamperRegistry
        .resolve(ts.plugins)
        .reduce((acc, pl) => pl.transform(acc, {}), p);
      const code = await getStatus(buildUrl(base, out));
      const ok = code === 200;
      if (ok) bypass++;
      detail.push(`  - "${p}" → [${ts.name}] "${out}" => HTTP ${code} ${ok ? '✓绕过' : '✗拦截'}`);
    }
    const rate = `${bypass}/${PAYLOADS.length}`;
    rows.push({ name: ts.name, rate, bypass, detail });
    console.log(`[${ts.name}] 绕过率 ${rate}`);
    detail.forEach((d) => console.log(d));
    console.log('');
  }
  const best = rows.reduce((a, b) => (b.bypass > a.bypass ? b : a));
  console.log(`结论：绕过率最高组合 = ${best.name}（${best.rate}）。`);
  console.log('注意：randomcase 对 /i 不敏感规则无效，如实反映——tamper 需按目标 WAF 特征选型。');
}

// —— 参数解析 ——
const args = process.argv.slice(2);
const urlIdx = args.indexOf('--url');
const remoteUrl = urlIdx >= 0 ? args[urlIdx + 1] : null;
const authorized = args.includes('--authorized');

if (remoteUrl) {
  if (!authorized) {
    console.error('⚠️ 远程联调模式需要显式确认授权（--authorized 缺失）。');
    console.error('该模式将向外部 URL 发送注入 payload，仅限已书面授权的目标使用。');
    console.error('如确已授权，请加 --authorized 重新运行：');
    console.error(`  node server/scripts/tamperBypassDemo.mjs --url "${remoteUrl}" --authorized`);
    process.exit(1);
  }
  console.log('=== tamper 远程联调模式（已确认授权）===');
  console.log('目标：%s\n', remoteUrl);
  await evaluate(remoteUrl);
  process.exit(0);
}

// —— 本地模式 ——
const PORT = 4569;
localServer.listen(PORT, async () => {
  const base = `http://localhost:${PORT}/`;
  console.log('=== sqli-scanner tamper 绕过 WAF 演示（本地靶机 :%d）===', PORT);
  console.log('WAF 规则：拦截 /union\\s+select/i 与 /and\\s+1=1/i\n');
  await evaluate(base);
  localServer.close();
});
