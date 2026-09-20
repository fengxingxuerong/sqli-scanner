// ============================================================================
// blackbox-lab / run-scan.mjs —— 两轮扫描驱动（r1 默认档 / r2 实战档）
//
// 铁律：
//   · 串行跑（时间盲注点对并发极敏感，并发会互相污染）
//   · 判定只读**报告产物**里的 vulns 数组，不看 CLI 自报的退出码/日志字样
//   · -o 用 Windows 原生路径（Git Bash 下 /D:/... 形式工具写不出来）
//   · 靶场由本脚本自拉起，避免「靶场没起」被误读成漏报
//
// 用法：node e2e/blackbox-lab/run-scan.mjs [--only=id1,id2] [--round=r1]
// ============================================================================

import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '../..');
const PORT = Number(process.env.LAB_PORT || 8099);
const BASE = `http://127.0.0.1:${PORT}`;
const OUT = path.join(HERE, 'out');
fs.mkdirSync(OUT, { recursive: true });

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function startLab(waf) {
  const proc = spawn('node', [path.join(HERE, 'lab-app.mjs')], {
    cwd: ROOT,
    env: { ...process.env, LAB_PORT: String(PORT), LAB_WAF: waf ? '1' : '0' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let log = '';
  proc.stdout.on('data', (d) => { log += d; });
  proc.stderr.on('data', (d) => { log += d; });
  for (let i = 0; i < 40; i++) {
    try {
      const r = await fetch(`${BASE}/__lab/health`);
      if (r.ok) return { proc, log: () => log };
    } catch { /* 未就绪 */ }
    await sleep(250);
  }
  try { proc.kill(); } catch { /* noop */ }
  throw new Error('靶场启动失败:\n' + log.slice(0, 600));
}

// ── 靶点 → CLI 参数映射 ─────────────────────────────────────────────────────
// 只列「已接进扫描」的点。真值表里另有 2 个点**从未被扫描过**（见 TODO §W）：
//   · D1-postform      POST 表单（/api/login，urlencoded 的 username）
//   · E1b-secondorder  二阶：先 POST /api/comment 写入，再用 admin 会话 GET /api/admin/orders 触发
// [2026-09-20 勘误] 这里原本写「由 run-scenario.mjs 单独处理」—— **该文件全仓不存在**
// （`find . -name "run-scenario*"` 零命中，本行是唯一提及处；out/ 里也没有这两点的任何产物）。
// 于是「真值标定 22 点」与「实际扫描 20 点」长期被混为一谈。现改为此事实陈述，
// 并由 scripts/lab-targets-check.mjs 的 scanGaps 显式登记（不再静默）。
// 补齐所需的 args 草案写在 TODO §W，**未验证，勿直接照抄**。
const POINTS = [
  { id: 'A1-numeric', url: '/api/user?id=1' },
  { id: 'A2-string', url: '/api/search?name=alice' },
  { id: 'A3-like', url: '/api/like?q=Keyboard' },
  { id: 'A4-orderby', url: '/api/sort?by=price' },
  { id: 'B1-error', url: '/api/product?id=1' },
  { id: 'C1-blindbool', url: '/api/blind?id=1' },
  { id: 'C2-blindtime', url: '/api/sleep?id=1', timeoutMs: 300000 },
  { id: 'D2-json', url: '/api/order', args: ['--method', 'POST', '--body', '{"item":"USB-C Hub"}'] },
  { id: 'D3-cookie', url: '/api/profile', args: ['--cookie', 'uid=1'] },
  { id: 'D4-xff', url: '/api/visitor', args: ['--header', 'X-Forwarded-For: alice'] },
  { id: 'D5-base64', url: '/api/encoded?d=MQ%3D%3D' },
  { id: 'D6-pathseg', url: '/api/rest/1', args: ['--test-path'] },
  { id: 'E2-stacked', url: '/api/batch?id=1' },
  // 安全对照（必须零检出）
  { id: 'F1-parametrized', kind: 'safe', url: '/api/safe/user?id=1' },
  { id: 'F2-nonce', kind: 'safe', url: '/api/safe/nonce' },
  { id: 'F3-const500', kind: 'safe', url: '/api/safe/error' },
  { id: 'F4-const403', kind: 'safe', url: '/api/safe/forbidden' },
  { id: 'F5-redirect', kind: 'safe', url: '/api/safe/redirect' },
  { id: 'F6-static', kind: 'safe', url: '/static/hello.html' },
  { id: 'F7-intval', kind: 'safe', url: '/api/safe/intval?id=1' },
];

// 两轮配置：默认档 = 开箱即用；实战档 = 拉满参数
const ROUNDS = {
  r1: { name: '默认档（开箱即用）', args: [] },
  r2: {
    name: '实战档（调参拉满）',
    args: ['--level', '5', '--risk', '3', '--technique', 'BEUSTQ', '--test-headers', '--test-path'],
  },
};

function runCli(point, round, outFile) {
  const args = ['server/bin/cli.js', '-u', BASE + point.url, '--format', 'json', '-o', outFile,
    ...(point.args || []), ...round.args];
  return new Promise((resolve) => {
    const t0 = Date.now();
    const p = spawn('node', args, { cwd: ROOT, stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '';
    p.stdout.on('data', (d) => { out += d; });
    p.stderr.on('data', (d) => { out += d; });
    const timer = setTimeout(() => { try { p.kill(); } catch { /* noop */ } }, point.timeoutMs || 240000);
    p.on('exit', (code) => {
      clearTimeout(timer);
      resolve({ code, ms: Date.now() - t0, log: out });
    });
  });
}

function readVerdict(outFile) {
  if (!fs.existsSync(outFile)) return { ok: false, reason: '报告未生成', vulns: [], dbms: null };
  let d;
  try {
    d = JSON.parse(fs.readFileSync(outFile, 'utf8'));
  } catch (e) {
    return { ok: false, reason: '报告解析失败: ' + e.message, vulns: [], dbms: null };
  }
  const vulns = d.vulns || [];
  return {
    ok: true,
    vulns,
    hit: vulns.length > 0,
    techniques: [...new Set(vulns.map((v) => v.technique).filter(Boolean))],
    dbms: d.dbms || null,
    points: (d.points || []).length,
    riskLevel: d.riskLevel || null,
    requests: d.summary?.validity?.counts?.total ?? null,
  };
}

async function main() {
  const argv = process.argv.slice(2);
  const onlyArg = argv.find((a) => a.startsWith('--only='));
  const only = onlyArg ? onlyArg.split('=')[1].split(',').map((s) => s.trim()) : null;
  const roundArg = argv.find((a) => a.startsWith('--round='));
  const roundKeys = roundArg ? [roundArg.split('=')[1]] : ['r1', 'r2'];
  const waf = argv.includes('--waf');

  const targets = only ? POINTS.filter((p) => only.includes(p.id)) : POINTS;
  const { proc } = await startLab(waf);
  console.log(`[run-scan] 靶场已起 ${BASE}  WAF=${waf ? 'ON' : 'OFF'}  点=${targets.length}`);

  const matrix = [];
  for (const roundKey of roundKeys) {
    const round = ROUNDS[roundKey];
    console.log(`\n=== 轮次 ${roundKey}：${round.name} ===`);
    for (const point of targets) {
      const outFile = path.join(OUT, `${point.id}.${roundKey}.json`);
      if (fs.existsSync(outFile)) fs.unlinkSync(outFile);
      const r = await runCli(point, round, outFile);
      const v = readVerdict(outFile);
      const row = {
        id: point.id,
        kind: point.kind || 'vuln',
        round: roundKey,
        exitCode: r.code,
        ms: r.ms,
        hit: v.hit,
        techniques: v.techniques,
        dbms: v.dbms,
        requests: v.requests,
        riskLevel: v.riskLevel,
        reason: v.ok ? null : v.reason,
      };
      matrix.push(row);
      const mark = row.kind === 'safe'
        ? (row.hit ? 'FALSE-POSITIVE' : 'clean')
        : (row.hit ? 'HIT' : 'MISS');
      console.log(`  ${point.id.padEnd(16)} ${mark.padEnd(15)} ${(row.ms / 1000).toFixed(1)}s` +
        `  tech=[${(row.techniques || []).join(',')}]  dbms=${row.dbms}  req=${row.requests}`);
    }
  }

  fs.writeFileSync(path.join(OUT, waf ? 'scan-matrix.waf.json' : 'scan-matrix.json'),
    JSON.stringify({ generatedAt: new Date().toISOString(), waf, rounds: roundKeys, matrix }, null, 2), 'utf8');

  // 汇总：按轮次分别统计
  console.log('\n=== 汇总 ===');
  for (const roundKey of roundKeys) {
    const rows = matrix.filter((r) => r.round === roundKey);
    const vulnRows = rows.filter((r) => r.kind === 'vuln');
    const safeRows = rows.filter((r) => r.kind === 'safe');
    const hit = vulnRows.filter((r) => r.hit).length;
    const fp = safeRows.filter((r) => r.hit).length;
    console.log(`  ${roundKey}: 漏洞检出 ${hit}/${vulnRows.length}` +
      `  安全误报 ${fp}/${safeRows.length}` +
      (fp ? `  ← 误报点: ${safeRows.filter((r) => r.hit).map((r) => r.id).join(',')}` : ''));
    const miss = vulnRows.filter((r) => !r.hit);
    if (miss.length) console.log(`         漏报点: ${miss.map((r) => r.id).join(',')}`);
  }

  try { proc.kill(); } catch { /* noop */ }
  console.log('\n[run-scan] 靶场已停止');
}

main().catch((e) => { console.error('[run-scan] 失败:', e.message); process.exit(2); });
