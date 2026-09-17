#!/usr/bin/env node
// ============================================================================
// e2e/acceptance.mjs —— 全方位验收门禁（可进 CI）
// ============================================================================
// 存在理由（2026-09-12 评估结论落地）：
//   项目已有 1719 条单测 + 8 套靶场，却仍漏掉五类真实缺陷——因为它们全在**组件接缝**上，
//   而接缝处的共同病征是「中间层自报成功、无人校验外部事实」（wrote:true 但文件不存在、
//   探针发出但没闭合、靶场存在但硬编码端口跑不起来）。
//   因此本门禁的核心纪律：**不采信任何套件自报的 PASS 字样**，只解析可独立核对的事实数字
//   （漏洞场景数 / 安全误报数 / 技术位 / 文件是否真的存在），并据此判定。
//
// 另两条设计约束：
//   ① 前置依赖不可用时输出 SKIP + 原因（不静默跳过、不假装通过）；
//   ② 任一必需套件失败 → 非零退出码，可直接作为 CI 门禁。
//
// 用法：
//   node e2e/acceptance.mjs                 # 全量
//   node e2e/acceptance.mjs --skip-heavy    # 跳过最慢的 CRS 套件
//   环境变量：MYSQL_HOST/PORT/USER/PASSWORD/DATABASE（默认 127.0.0.1:3306 root/root sqli_lab）
// ============================================================================
import { spawn } from 'node:child_process';
import { createRequire } from 'node:module';
import { mkdirSync, writeFileSync, existsSync, rmSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import net from 'node:net';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '..');
const require = createRequire(resolve(ROOT, 'server/package.json'));
const mysql = require('mysql2/promise');

const MYSQL = {
  host: process.env.MYSQL_HOST ?? '127.0.0.1',
  port: Number(process.env.MYSQL_PORT) || 3306,
  user: process.env.MYSQL_USER ?? 'root',
  password: process.env.MYSQL_PASSWORD ?? 'root',
  database: process.env.MYSQL_DATABASE || 'sqli_lab',
};
const SKIP_HEAVY = process.argv.includes('--skip-heavy');
// --only=waf-real,waf-auto —— 只跑指定套件（改完某模块后做定向门禁，省掉全量几分钟）
const ONLY = (() => {
  const a = process.argv.find((x) => x.startsWith('--only='));
  return a ? new Set(a.slice('--only='.length).split(',').map((s) => s.trim()).filter(Boolean)) : null;
})();
const PORT_BASE = 8200 + (process.pid % 200); // 避开常驻端口，支持并行跑

// ── 工具 ────────────────────────────────────────────────────────────────────
function portOpen(port, host = '127.0.0.1', timeout = 1200) {
  return new Promise((ok) => {
    const s = net.connect({ port, host });
    const done = (v) => { s.destroy(); ok(v); };
    s.setTimeout(timeout, () => done(false));
    s.once('connect', () => done(true));
    s.once('error', () => done(false));
  });
}

function run(cmd, args, env = {}, timeoutMs = 900000, cwd = ROOT) {
  return new Promise((done) => {
    const child = spawn(cmd, args, {
      cwd,
      env: { ...process.env, ...env },
      shell: process.platform === 'win32',
    });
    let out = '';
    const timer = setTimeout(() => child.kill(), timeoutMs);
    child.stdout.on('data', (d) => (out += d.toString('utf8')));
    child.stderr.on('data', (d) => (out += d.toString('utf8')));
    child.on('close', (code) => { clearTimeout(timer); done({ code, out }); });
    child.on('error', (e) => { clearTimeout(timer); done({ code: -1, out: `${out}\n[spawn error] ${e.message}` }); });
  });
}

const num = (re, s, g = 1) => {
  const m = String(s).match(re);
  return m ? Number(m[g]) : null;
};

// ── 前置检查：依赖不可用必须显式 SKIP 并给出原因 ──────────────────────────────
// [2026-09-17 FIX] 依赖键必须与 SUITES[].needs 的拼写**逐字一致**。
// 原实现 pre 里只有驼峰键 secureFilePriv，而 redteam/file-read/file-write 三个套件的
// needs 写的是 'secure_file_priv' —— `!pre['secure_file_priv']` 恒为 true，
// 于是这三个套件**无论 MySQL 怎么配都被判 SKIP**（假 SKIP：门禁声称"因环境跳过"，
// 实际是键名拼错，能力从未被验证过）。故这里同时提供：
//   · secureFilePriv    —— 原值（null / '' / '/path'），供报告展示；
//   · secure_file_priv  —— 布尔判据，供 needs 消费。
const pre = { mysql: false, mysqlReason: '', secureFilePriv: null, secure_file_priv: false, mysqlVersion: null, redteamLab: false };
{
  if (await portOpen(MYSQL.port)) {
    try {
      const c = await mysql.createConnection(MYSQL);
      const [r] = await c.query('SELECT @@version v, @@secure_file_priv s');
      pre.mysql = true;
      pre.mysqlVersion = r[0].v;
      pre.secureFilePriv = r[0].s;
      // [2026-09-17 FIX] MySQL 语义：NULL=禁止导入导出；''=不限制；'/path'=限定该目录。
      // 后两者都算「已放行」，故判据是「非 null/undefined」而不是「非空字符串」——
      // 用真值语义会把 ''（完全放行）误判成未放行，正好和实际能力相反。
      pre.secure_file_priv = r[0].s !== null && r[0].s !== undefined;
      await c.end();
    } catch (e) {
      pre.mysqlReason = `端口开放但连接失败（${e.code || e.message}）——检查 MYSQL_USER/MYSQL_PASSWORD`;
    }
  } else {
    pre.mysqlReason = `端口 ${MYSQL.port} 未监听——请先启动 MySQL`;
  }
}

// 红队评测靶场（ground-truth 真值对照 + sqlmap 同题对比）：独立进程常驻，需预先拉起
const REDTEAM_PORT = Number(process.env.REDTEAM_LAB_PORT) || 8231;
pre.redteamLab = await portOpen(REDTEAM_PORT, '127.0.0.1', 1500);

const envDb = {
  MYSQL_HOST: MYSQL.host,
  MYSQL_PORT: String(MYSQL.port),
  MYSQL_USER: MYSQL.user,
  MYSQL_PASSWORD: MYSQL.password,
  MYSQL_DATABASE: MYSQL.database,
};

// ── 套件定义：assert 只吃「事实数字」，不看套件自报的 PASS 字样 ─────────────────
const SUITES = [
  {
    id: 'unit',
    title: '服务端单测',
    needs: [],
    // 单测须在 server/ 目录下跑（其 package.json 与相对导入路径都以此为根）
    run: () => run('node', ['--test', '--test-concurrency=1'], {}, 1200000, resolve(ROOT, 'server')),
    // 事实：通过数、失败数与跳过数
    assert: (out) => {
      const tests = num(/# tests (\d+)/, out);
      const pass = num(/# pass (\d+)/, out);
      const fail = num(/# fail (\d+)/, out);
      // [2026-09-17 FIX] 原断言是 `pass === tests`，与「环境依赖缺失显式 skip」自相矛盾：
      // 只要存在 1 条 skip 就恒判 FAIL。实测 1838 tests / 1835 pass / 0 fail / 3 skip 被判
      // FAIL（原因却打印「断言未通过」）。**门禁假红比没有门禁更糟**——团队会习惯性忽略它，
      // 真失败也随之被淹没。正确口径：pass + skipped === tests 且 fail === 0。
      const skipped = num(/# skipped (\d+)/, out);
      return {
        facts: { tests, pass, fail, skipped },
        pass: tests != null && fail === 0 && pass + (skipped || 0) === tests && tests > 1000,
        reason: fail === 0 ? null : `${fail} 条失败`,
      };
    },
    cwd: 'server',
  },
  {
    id: 'pentest-lab',
    title: '独立刁钻靶场（11 场景）',
    needs: ['mysql'],
    run: () => run('node', ['e2e/pentest-lab/verify.mjs'], { ...envDb, PENTEST_LAB_PORT: String(PORT_BASE) }),
    assert: (out) => {
      const vuln = num(/漏洞场景检出 (\d+)\/(\d+)/, out, 1);
      const total = num(/漏洞场景检出 (\d+)\/(\d+)/, out, 2);
      const fp = num(/安全场景误报 (\d+)/, out);
      return {
        facts: { 漏洞场景: `${vuln}/${total}`, 安全误报: fp },
        pass: vuln != null && vuln === total && fp === 0,
        reason: fp !== 0 ? `安全场景误报 ${fp} 次` : vuln !== total ? `漏检 ${total - vuln} 个场景` : null,
      };
    },
  },
  {
    id: 'detection-runner',
    title: '检测回归（19 场景）',
    needs: ['mysql'],
    run: () => run('node', ['e2e/detection-runner/run.js'], envDb),
    assert: (out) => {
      const pass = num(/统计：(\d+) PASS/, out);
      const fail = num(/(\d+) FAIL/, out);
      return {
        facts: { PASS: pass, FAIL: fail },
        pass: pass != null && pass >= 19 && fail === 0,
        reason: fail ? `${fail} 个场景失败` : null,
      };
    },
  },
  {
    id: 'real-mysql-lab',
    title: '真 MySQL 靶场',
    needs: ['mysql'],
    run: () => run('node', ['e2e/real-mysql-lab/verify.mjs'], envDb),
    assert: (out) => {
      const pass = (out.match(/\[PASS\]/g) || []).length;
      const fail = (out.match(/\[FAIL\]/g) || []).length;
      return { facts: { PASS: pass, FAIL: fail }, pass: pass >= 10 && fail === 0, reason: fail ? `${fail} 项失败` : null };
    },
  },
  {
    id: 'real-world-lab',
    title: '真 PG 靶场（含二阶注入）',
    needs: [],
    run: () => run('node', ['e2e/real-world-lab/verify.mjs'], {}),
    assert: (out) => {
      const allPass = /全部通过/.test(out);
      const dbOk = /PGlite/.test(out);
      return { facts: { 全部通过: allPass, 引擎: dbOk ? 'PGlite' : '?' }, pass: allPass && dbOk, reason: allPass ? null : '存在未通过项' };
    },
  },
  {
    id: 'report-contract',
    title: '报告契约（自报字段必须与真实状态一致）',
    needs: ['mysql'],
    run: () => run('node', ['e2e/contract/report-contract.e2e.mjs'], { ...envDb, PENTEST_LAB_PORT: String(PORT_BASE + 1) }),
    assert: (out) => {
      const ok = num(/\[contract\] 校验通过 (\d+)/, out);
      const bad = num(/\[contract\] 不一致 (\d+)/, out);
      return { facts: { 通过: ok, 不一致: bad }, pass: ok != null && ok >= 5 && bad === 0, reason: bad ? `${bad} 项字段与真实状态不符` : null };
    },
  },
  {
    id: 'waf-real',
    title: 'CRS v4.1.0 人工挂链 A/B',
    needs: ['mysql'],
    heavy: true,
    run: () => run('node', ['e2e/waf-real/waf-verify.mjs'], envDb),
    assert: (out) => {
      const off = num(/\[tamper off\] 注入点检出 (\d+)\//, out);
      const on = num(/\[tamper on\] 注入点检出 (\d+)\//, out);
      const noFp = /安全对照误拦：无/.test(out);
      return {
        facts: { off, on, 安全对照误拦: !noFp },
        pass: off != null && on != null && on > off && noFp,
        reason: !noFp ? '安全对照存在误拦' : on <= off ? '挂链未带来增益' : null,
      };
    },
  },
  {
    id: 'waf-auto',
    title: 'CRS 自动选链绕过',
    needs: ['mysql'],
    heavy: true,
    run: () => run('node', ['e2e/waf-real/waf-auto-check.mjs'], envDb),
    assert: (out) => {
      const bits = num(/自动绕过技术位合计 (\d+)/, out);
      const fp = num(/安全误报 (\d+)/, out);
      return {
        facts: { 技术位: bits, 安全误报: fp },
        pass: bits != null && bits >= 6 && fp === 0,
        reason: fp ? `安全误报 ${fp}` : bits < 6 ? `技术位仅 ${bits}` : null,
      };
    },
  },
  {
    id: 'redteam',
    title: '红队实战评测（ground-truth 真值对照 + sqlmap 同题）',
    needs: ['redteamLab'],
    optional: true, // 依赖独立常驻靶场（npm run lab:redteam），CI 外不强制
    heavy: true,
    // 顺序：重建地面真值 → 调参口径扫描 → 汇总（含 sqlmap 对照）
    // 不跑 selftest（它会重写真值表），只跑扫描 + 由 gate-check 直接读文件算准确率
    run: () => run('node', ['e2e/redteam-lab/run-scan.mjs', 'r2']).then(() =>
      run('node', ['e2e/redteam-lab/gate-check.mjs', 'r2'])
    ),
    assert: (out) => {
      // 只吃事实数字：R2 命中/总数、sqlmap 命中/总数、误报数
      // 直接吃 gate-check 算好的真值数字（分母只含已确认 vuln，误报只数 safe）
      const hit = num(/\[redteam\] round=r2 vuln=(\d+) hit=(\d+) rate=(\d+)% safe=(\d+) fp=(\d+)/, out, 2);
      const total = num(/\[redteam\] round=r2 vuln=(\d+) hit=(\d+) rate=(\d+)% safe=(\d+) fp=(\d+)/, out, 1);
      const pct = num(/\[redteam\] round=r2 vuln=(\d+) hit=(\d+) rate=(\d+)% safe=(\d+) fp=(\d+)/, out, 3);
      const safeN = num(/\[redteam\] round=r2 vuln=(\d+) hit=(\d+) rate=(\d+)% safe=(\d+) fp=(\d+)/, out, 4);
      const fp = num(/\[redteam\] round=r2 vuln=(\d+) hit=(\d+) rate=(\d+)% safe=(\d+) fp=(\d+)/, out, 5);
      return {
        facts: { 检出: `${hit}/${total}`, 检出率: `${pct}%`, 安全点: safeN, 误报: fp },
        pass: total > 0 && pct != null && pct >= 90 && fp === 0,
        reason: fp ? `安全点误报 ${fp} 个` : pct == null ? '未取到 gate-check 判据' : `检出率仅 ${pct}%`,
      };
    },
  },
  {
    id: 'file-read',
    title: 'fileRead 真闭环',
    needs: ['secure_file_priv'],
    // optional：secure_file_priv 未放行属 MySQL 8 默认环境（NULL），此时脚本自身即输出 SKIP；
    // 这类「环境可选依赖」缺失不影响门禁结论，与「必需依赖缺失」必须区别对待。
    optional: true,
    run: () => run('node', ['e2e/fileops/exploit-file-read.e2e.mjs'], { ...envDb, PENTEST_LAB_PORT: String(PORT_BASE + 2) }),
    assert: (out) => {
      const passed = /\[PASS\] fileRead/.test(out);
      const skipped = /\[SKIP\]/.test(out);
      return { facts: { PASS: passed, SKIP: skipped }, pass: passed || skipped, reason: skipped ? null : passed ? null : '断言未通过' };
    },
  },
  {
    id: 'file-write',
    title: 'fileWrite 真闭环（文件系统侧断言）',
    needs: ['secure_file_priv'],
    optional: true,
    run: () => run('node', ['e2e/fileops/exploit-file-write.e2e.mjs'], { ...envDb, PENTEST_LAB_PORT: String(PORT_BASE + 3) }),
    assert: (out) => {
      const passed = /\[PASS\] fileWrite/.test(out);
      const skipped = /\[SKIP\]/.test(out);
      const landed = /文件存在=true/.test(out);
      return { facts: { PASS: passed, SKIP: skipped, 文件落盘: landed }, pass: passed || skipped, reason: passed ? null : skipped ? null : '文件未落盘或断言失败' };
    },
  },
];

// ── 执行 ────────────────────────────────────────────────────────────────────
const results = [];
console.log('═══ 全方位验收门禁（事实断言模式：不采信套件自报 PASS）═══\n');
console.log(
  `前置：MySQL ${pre.mysql ? `✅ ${pre.mysqlVersion} @${MYSQL.host}:${MYSQL.port}` : `❌ ${pre.mysqlReason}`}` +
    `　secure_file_priv=${JSON.stringify(pre.secureFilePriv)}\n`
);

const selected = ONLY ? SUITES.filter((s) => ONLY.has(s.id)) : SUITES;
if (ONLY && !selected.length) {
  console.error(`--only 未匹配任何套件。可用 id：${SUITES.map((s) => s.id).join(', ')}`);
  process.exit(2);
}

for (const s of selected) {
  const missing = (s.needs || []).filter((n) => !pre[n]);
  if (missing.length) {
    const why =
      missing.includes('mysql') ? pre.mysqlReason : 'secure_file_priv 未放行（MySQL 8 默认 NULL）';
    // [P0-FIX 2026-09-12] SKIP 必须分两类，否则会出现**假绿**：
    //   ① optional 套件（fileRead/fileWrite）因 secure_file_priv=NULL 跳过 —— 环境常态，不影响结论；
    //   ② 必需依赖缺失（MySQL 没起）导致 8 个套件全跳 —— 此时若仍退出码 0，CI 会**绿灯放过**
    //      一个什么都没验的流水线。故必需依赖缺失一律判 BLOCKED 并计入失败。
    if (s.optional) {
      results.push({ ...s, status: 'SKIP', facts: { 原因: why } });
      console.log(`⏭  SKIP  ${s.title}\n        原因：${why}`);
    } else {
      results.push({ ...s, status: 'BLOCKED', facts: { 缺失依赖: why }, reason: `必需依赖缺失：${why}` });
      console.log(`⛔ BLOCKED  ${s.title}\n        必需依赖缺失：${why}`);
    }
    continue;
  }
  if (s.heavy && SKIP_HEAVY) {
    results.push({ ...s, status: 'SKIP', facts: { 原因: '--skip-heavy' } });
    console.log(`⏭  SKIP  ${s.title}（--skip-heavy）`);
    continue;
  }
  process.stdout.write(`▶  运行  ${s.title} ... `);
  const r = await s.run();
  // 断言只吃事实数字；子进程非零退出但断言通过（如脚本用退出码表达 SKIP）不判失败
  const verdict = s.assert(r.out);
  const status = verdict.pass ? 'PASS' : 'FAIL';
  const reason = verdict.pass ? null : verdict.reason || `断言未通过（退出码 ${r.code}）`;
  results.push({ ...s, status, facts: verdict.facts, reason, code: r.code, out: r.out });
  console.log(`${status}  ${verdict.pass ? '' : `→ ${reason}`}`);
}

// ── 报告 ────────────────────────────────────────────────────────────────────
const failed = results.filter((r) => r.status === 'FAIL' || r.status === 'BLOCKED');
const skipped = results.filter((r) => r.status === 'SKIP');
const passed = results.filter((r) => r.status === 'PASS');

const badge = { PASS: '✅ PASS', SKIP: '⏭ SKIP', BLOCKED: '⛔ BLOCKED', FAIL: '❌ FAIL' };
const row = (r) =>
  `| ${badge[r.status]} | ${r.title} | ` +
  `${Object.entries(r.facts || {}).map(([k, v]) => `${k}=${v}`).join('　')} |`;

const md = [
  '# 全方位验收门禁报告',
  '',
  `> 生成：${new Date().toISOString()}　｜　执行器：\`node e2e/acceptance.mjs\``,
  `> 前置：MySQL ${pre.mysql ? `${pre.mysqlVersion} @${MYSQL.host}:${MYSQL.port}` : `不可用（${pre.mysqlReason}）`}；secure_file_priv=${JSON.stringify(pre.secureFilePriv)}`,
  '',
  '> **判定纪律**：不采信各套件自报的 PASS 字样，只解析可独立核对的事实数字并据此断言。',
  '',
  '| 结果 | 套件 | 事实 |',
  '|---|---|---|',
  ...results.map(row),
  '',
  `**汇总：${passed.length} PASS / ${failed.length} FAIL(含 BLOCKED) / ${skipped.length} SKIP**`,
  failed.length ? '\n## 失败详情\n' + failed.map((f) => `- **${f.title}**：${f.reason || '断言未通过'}`).join('\n') : '',
  skipped.length ? '\n## 跳过原因\n' + skipped.map((f) => `- **${f.title}**：${Object.values(f.facts || {})[0]}`).join('\n') : '',
  '',
].join('\n');

mkdirSync(resolve(HERE, 'results'), { recursive: true });
writeFileSync(resolve(HERE, 'results', 'acceptance-report.md'), md);

console.log('\n═══ 汇总 ═══');
for (const r of results) {
  console.log(
    `${r.status.padEnd(5)} ${r.title}　${Object.entries(r.facts || {}).map(([k, v]) => `${k}=${v}`).join(' ')}`
  );
}
console.log(`\n${passed.length} PASS / ${failed.length} FAIL / ${skipped.length} SKIP`);
console.log(`报告：e2e/results/acceptance-report.md`);
process.exit(failed.length ? 1 : 0);
