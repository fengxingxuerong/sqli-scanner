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
import { mkdirSync, writeFileSync, readFileSync, rmSync, existsSync } from 'node:fs';
import { dirname, resolve, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import net from 'node:net';
// [DECISION-2026-09-22] 套件状态判定（含「沙箱起不来」三形态识别）抽成可单测模块
import { classifySuite } from './lib/suiteVerdict.mjs';

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

// ── 代码版本凭证 ────────────────────────────────────────────────────────────
// [2026-09-20 新增] 报告此前只有时间戳，回答不了「这份 N PASS 是哪一版代码跑出来的」。
// 与 facts 那次假绿同源（TODO §Q）：结论没绑到版本上，代码变了报告还留着旧结论。
// 更麻烦的是**工作区 dirty 时跑出的报告会被提交进库** —— 读的人会以为它对应某个提交。
// 故：记录 HEAD + 未提交清单，dirty 时显式标注「本报告不对应任何提交」。
//
// 时序要求：必须在**验收开始前**采集。跑验收本身会写 e2e/*/results/*，
// 结束时再采集会把「运行产物」误读成「跑之前的未提交改动」，反过来说谎。
async function gitStamp() {
  const head = await run('git', ['rev-parse', '--short', 'HEAD']);
  if (head.code !== 0) return { head: '(非 git 工作区)', dirty: [] };
  const st = await run('git', ['status', '--porcelain']);
  // porcelain 每行 = `XY<space>path`，故 slice(3)。行尾 \r 要剥掉（Windows 上 git 仍输出 LF，
  // 但不值得为它赌一次），空行必须滤掉（输出尾部一定有）。
  const dirty = st.out
    .split('\n').map((l) => l.replace(/\r$/, '')).filter((l) => l.trim())
    .map((l) => l.slice(3).trim());
  return { head: head.out.trim(), dirty };
}

// ── 前置检查：依赖不可用必须显式 SKIP 并给出原因 ──────────────────────────────
// [2026-09-17 FIX] 依赖键必须与 SUITES[].needs 的拼写**逐字一致**。
// 原实现 pre 里只有驼峰键 secureFilePriv，而 redteam/file-read/file-write 三个套件的
// needs 写的是 'secure_file_priv' —— `!pre['secure_file_priv']` 恒为 true，
// 于是这三个套件**无论 MySQL 怎么配都被判 SKIP**（假 SKIP：门禁声称"因环境跳过"，
// 实际是键名拼错，能力从未被验证过）。故这里同时提供：
//   · secureFilePriv    —— 原值（null / '' / '/path'），供报告展示；
//   · secure_file_priv  —— 布尔判据，供 needs 消费。
// [2026-09-20] 代码版本凭证：必须在任何套件开跑**之前**采集（跑起来会写 e2e/*/results/*，
// 之后再采集就把运行产物当成未提交改动了）。详见 gitStamp() 注释。
const git = await gitStamp();

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

// CRS 靶场的技术位基线（按 PL 分别锁，只减不增）。缺文件就**直接终止**而不是"没基线就当通过"——
// 那正是本仓栽过的假绿形态。改档：WAF_GATE_PL=3 npm run acceptance。
const WAF_GATE_PL = Number(process.env.WAF_GATE_PL) || 1;
let WAF_BASELINE;
try {
  WAF_BASELINE = JSON.parse(readFileSync(resolve(ROOT, 'e2e/waf-real/waf-bits-baseline.json'), 'utf8'));
} catch (e) {
  console.error(`❌ 读不到 e2e/waf-real/waf-bits-baseline.json（${e.message}）—— WAF 两套件无基线可判，拒绝跑`);
  process.exit(2);
}

// 红队靶场是独立常驻进程（PG + 8231）。以前"没常驻"就 SKIP —— 于是这一格既不会红、也永远不测。
// 现在缺就自己拉起来，跑完收掉；只有真起不动（典型：本机没有 PostgreSQL）才落回 SKIP 并写明原因。
async function withRedteamLab(body) {
  if (pre.redteamLab) return body();
  console.log('    （红队靶场未常驻：自己拉起 env.mjs，跑完会收掉）');
  const proc = spawn('node', ['e2e/redteam-lab/env.mjs'], { cwd: ROOT, stdio: 'ignore', shell: process.platform === 'win32' });
  let up = false;
  for (let i = 0; i < 60; i++) {
    if (await portOpen(REDTEAM_PORT, '127.0.0.1', 1000)) { up = true; break; }
    await new Promise((r) => setTimeout(r, 1000));
  }
  try {
    return up ? await body() : { code: 0, out: '[SKIP] 自起红队靶场失败（120s 内 8231 未就绪，多半是缺 PostgreSQL）' };
  } finally {
    try { proc.kill(); } catch { /* 已退出 */ }
  }
}

// ── 套件定义：assert 只吃「事实数字」，不看套件自报的 PASS 字样 ─────────────────
const SUITES = [
  {
    id: 'unit',
    title: '服务端单测',
    needs: [],
    // 单测须在 server/ 目录下跑（其 package.json 与相对导入路径都以此为根）
    // [GATE-FIX 2026-09-19] 必须显式钉 `--test-reporter=tap`：下面的断言只认 TAP 汇总行
    // （`# tests/# pass/# fail/# skipped`），而 node:test 的 reporter 选型取决于 stdout 的 TTY
    // 探测 —— 本机（Windows + Git Bash）子进程走管道时输出的是 spec 格式（`ℹ tests 1885`），
    // 于是四个 num() 全取到 null → `fail === 0` 判假 → **门禁假红**，报告里那行写着
    // 「FAIL　tests=null pass=null fail=null」，一眼看不出是没测到而不是测挂了。
    // 同一坑已在此前的 scripts/facts-sync.mjs 修过一次（还咬过 3d63b7 那轮回流解析），
    // 三处共同的前置修复应是给 run() 统一加 reporter/stdout 口径。
    run: () => run('node', ['--test', '--test-reporter=tap', '--test-concurrency=1'], {}, 1200000, resolve(ROOT, 'server')),
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
      // 取不到汇总行 = **门禁自己坏了**，绝不能报成「单测失败」（也不该报成通过）。
      // 与本次 reporter 修复配套：以后格式再漂，报的是「解析不到」这个真原因，而不是 null 条失败。
      if (tests == null || pass == null || fail == null) {
        return {
          facts: { tests, pass, fail, skipped },
          pass: false,
          reason: '解析不到 TAP 汇总行（门禁取数口径与测试输出格式不符，非单测失败）',
        };
      }
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
    title: `CRS 人工挂链 A/B（PL${WAF_GATE_PL} 档基线）`,
    needs: ['mysql'],
    heavy: true,
    run: () => run('node', ['e2e/waf-real/waf-verify.mjs'], { ...envDb, CRS_PL: String(WAF_GATE_PL) }),
    assert: (out) => {
      // [BASELINE-FIX 2026-09-19] 原断言是 `on > off`（"挂链必须有增益"）。用 CRS 官方回归集把执行器
      // 修准之后该断言在两档上都不成立：PL1 下 off=on=8（探针本来就能通过默认部署的 CRS，无需绕过）、
      // PL3 下 off=on=0（全规则档全拦）。所以旧口径那句「tamper off 2 → on 8，绕过生效」是
      // **宽松执行器白给的假收益**（保真度 60.7% 时测的）。现在锁的是"不低于该档基线 + 安全对照零误拦"，
      // 基线按 PL 分别写在 e2e/waf-real/waf-bits-baseline.json（只减不增）。
      const off = num(/\[tamper off\] 技术位合计 (\d+)/, out);
      const on = num(/\[tamper on\] 技术位合计 (\d+)/, out);
      const noFp = /安全对照误拦：无/.test(out);
      const b = WAF_BASELINE.bits?.[String(WAF_GATE_PL)];
      if (!b) return { facts: { 错误: '基线缺该档' }, pass: false, reason: `waf-bits-baseline.json 里没有 PL${WAF_GATE_PL} 的条目` };
      return {
        facts: { off, on, 基线: `off≥${b.realOff} on≥${b.realOn}`, 安全对照误拦: !noFp },
        pass: off != null && on != null && noFp && off >= b.realOff && on >= b.realOn,
        reason: !noFp ? '安全对照存在误拦' : off < b.realOff || on < b.realOn ? `低于 PL${WAF_GATE_PL} 基线（off ${off}/${b.realOff}，on ${on}/${b.realOn}）` : null,
      };
    },
  },
  {
    id: 'waf-auto',
    title: `CRS 自动选链绕过（PL${WAF_GATE_PL} 档基线）`,
    needs: ['mysql'],
    heavy: true,
    run: () => run('node', ['e2e/waf-real/waf-auto-check.mjs'], { ...envDb, CRS_PL: String(WAF_GATE_PL) }),
    assert: (out) => {
      const bits = num(/自动绕过技术位合计 (\d+)/, out);
      const fp = num(/安全误报 (\d+)/, out);
      const floor = WAF_BASELINE.bits?.[String(WAF_GATE_PL)]?.auto ?? 0;
      return {
        facts: { 技术位: bits, 基线: `≥${floor}`, 安全误报: fp },
        pass: bits != null && bits >= floor && fp === 0,
        reason: fp ? `安全误报 ${fp}` : bits < floor ? `技术位 ${bits} < PL${WAF_GATE_PL} 基线 ${floor}` : null,
      };
    },
  },
  {
    // [P1-ADD 2026-09-19] 本仓所有 WAF 数字都出自**自实现 SecRule 执行器**（本机无 Docker/Go，
    // 跑不了真 ModSecurity/Coraza）。执行器不可信 → 那些数字全部作废。此套件用 CRS 官方回归集
    // （805 条带"该拦/不该拦"期望的用例，规则作者写的断言，不是我们自证的循环）验收保真度，
    // 并把分歧按"只减不增"基线点名。它不需要 MySQL，属于任何环境都该跑的一类。
    id: 'crs-fidelity',
    title: 'CRS 执行器保真度（官方回归集）',
    needs: [],
    run: () => run('node', ['e2e/waf-real/crs-equivalence.mjs'], {}),
    assert: (out) => {
      const rate = num(/剔除后逐规则一致率 ([\d.]+)%/, out);
      const unknown = num(/未点名 (\d+) 条/, out);
      const stale = num(/已消失 (\d+) 条/, out);
      const fp = num(/误触该规则 (\d+)（/, out);
      return {
        facts: { 保真度: rate == null ? null : `${rate}%`, 未点名分歧: unknown, 已消失: stale, 误触: fp },
        pass: rate != null && rate >= 90 && unknown === 0,
        reason:
          rate == null ? '取不到保真度行（输出格式变了？）' :
          rate < 90 ? `保真度 ${rate}% < 90%，WAF 数字不可对外引用` :
          unknown ? `出现 ${unknown} 条未点名分歧（看 e2e/waf-real/crs-equivalence.md）` : null,
      };
    },
  },
  {
    // [A2-ENDPOINT 2026-09-23] 定向变异搜索（T2）的端到端验收。
    // 与上面两个 CRS 套件**不重复**：它们答的是「绕过之后检出多少」，本套件答的是
    // 「引擎到底有没有去试那些按被拦词组合出来的链」——没有它，A2 可以接了线却一次都不生效，
    // 而所有套件照样绿（真实成因：静态候选 4 条 > MAX_CHAINS 3 条，生成链永远排在第 5 位）。
    // A/B 双向：开档必须验到生成链、关档必须一条都没有，且两档验证总条数相同（预算纪律）。
    // 自包含（不需要 MySQL/DB）—— 验的是选链层，故任何环境都该跑。
    id: 'waf-bypass-search',
    title: 'WAF 定向变异搜索（A2）端到端',
    needs: [],
    run: () => run('node', ['e2e/waf-real/waf-bypass-search.e2e.mjs'], {}),
    assert: (out) => {
      // 前提不满足（裸探针没被拦 / 靶场没起来）→ 一条断言都没执行，算 SKIP 不是通过
      if (/\[BLOCKED\]/.test(out)) {
        return {
          pass: false,
          skipped: true,
          skipReason: (/\[BLOCKED\] (.+)/.exec(out) || [, 'CRS 未生效，未执行断言'])[1].trim(),
        };
      }
      const on = num(/生成链验证 A档=(\d+) 条/, out);
      const off = num(/B档=(\d+) 条/, out);
      const nOn = num(/验证总数 on=(\d+)/, out);
      const nOff = num(/off=(\d+)/, out);
      const reason =
        on == null || off == null ? '取不到生成链计数（输出格式变了？）'
          : on < 1 ? `A 档未验证到任何生成链（A2 未生效：静态链占满名额？）`
          : off !== 0 ? `B 档（关闭开关）仍出现 ${off} 条生成链 —— 开关失效`
          : nOn !== nOff ? `开启定向搜索改变了验证条数（${nOn} vs ${nOff}）—— 违反预算纪律`
          : null;
      return {
        facts: { 'A档生成链': on, 'B档生成链': off, 验证条数: `${nOn}/${nOff}` },
        pass: reason === null,
        reason,
      };
    },
  },
  {
    id: 'redteam',
    title: '红队实战评测（ground-truth 真值对照 + sqlmap 同题）',
    needs: [],          // 自己会拉起 env（缺 PG 时才落回 SKIP），不再要求外部常驻
    optional: true,     // 起不动时算 SKIP（环境常态），不判红
    heavy: true,
    // 顺序：调参口径扫描 → 由 gate-check 直接读文件算准确率
    // 不跑 selftest（它会重写真值表）
    run: () => withRedteamLab(async () => {
      await run('node', ['e2e/redteam-lab/run-scan.mjs', 'r2']);
      return run('node', ['e2e/redteam-lab/gate-check.mjs', 'r2']);
    }),
    assert: (out) => {
      // 自起失败（典型：本机没 PG）→ 报 SKIP 而不是 FAIL：没测过不该判红，但也不能算通过
      if (/\[SKIP\]/.test(out) && !/\[redteam\] round=r2/.test(out)) {
        return { pass: false, skipped: true, skipReason: (/\[SKIP\] (.+)/.exec(out) || [, '红队靶场未就绪'])[1].trim() };
      }
      // 只吃事实数字：gate-check 算好的真值（分母只含已确认 vuln，误报只数 safe 点）
      const m = /\[redteam\] round=r2 vuln=(\d+) hit=(\d+) rate=(\d+)% safe=(\d+) fp=(\d+)/.exec(out) || [];
      const [, total, hit, pct, safeN, fp] = m;
      return {
        facts: { 检出: `${hit}/${total}`, 检出率: pct == null ? null : `${pct}%`, 安全点: safeN, 误报: fp },
        pass: Number(total) > 0 && pct != null && Number(pct) >= 90 && Number(fp) === 0,
        reason: fp && Number(fp) > 0 ? `安全点误报 ${fp} 个` : pct == null ? '未取到 gate-check 判据（输出格式变了？）' : Number(pct) < 90 ? `检出率仅 ${pct}%` : null,
      };
    },
  },
  {
    id: 'file-read',
    title: 'fileRead 真闭环',
    needs: ['secure_file_priv'],
    optional: true,
    // [SELF-HEAL 2026-09-19] 宿主 mysqld 没放行 secure_file_priv 时不再直接 SKIP：
    // 改用仓库自带的隔离 MySQL 沙箱重试一次（沙箱把 secure_file_priv 指到自己的 plugin 目录，
    // 套件会把标记文件放进那个目录）。2026-09-19 实测：两套件在沙箱内均真跑 PASS。
    // 只有"沙箱也起不来"（缺 python / 缺 mysqld 二进制）才落到 SKIP，并写清缺什么。
    run: async () => {
      const r1 = await run('node', ['e2e/fileops/exploit-file-read.e2e.mjs'], { ...envDb, PENTEST_LAB_PORT: String(PORT_BASE + 2) });
      if (!/\[SKIP\]/.test(r1.out)) return r1;
      const r2 = await run('python', ['e2e/run-with-sandbox.py', 'e2e/fileops/exploit-file-read.e2e.mjs'], {}, 600000);
      return { ...r2, out: `${r1.out}\n—— 宿主未放行，改用隔离沙箱重试 ——\n${r2.out}` };
    },
    assert: (out) => {
      // 走过沙箱重试时，判定只看**重试那一段**：否则第一次的 [SKIP] 文案会和最终的 [PASS] 混在
      // 同一行事实里，报出「PASS=true SKIP=true」这种看着就自相矛盾的东西。
      const tail = out.includes('改用隔离沙箱重试') ? out.split('改用隔离沙箱重试 ——').pop() : out;
      const viaSandbox = tail !== out;
      const passed = /\[PASS\] fileRead/.test(tail);
      const skipped = /\[SKIP\]/.test(tail);
      // [SKIP-FIX 2026-09-19] 只跳过、未执行断言时不再报 PASS（见下面 skippedOnly 的处理）。
      const v = {
        facts: { PASS: passed, SKIP: skipped, 方式: viaSandbox ? '隔离沙箱重试' : '宿主实例' },
        pass: passed || skipped,
        reason: skipped ? null : passed ? null : '断言未通过',
      };
      if (skipped && !passed) {
        v.skipped = true;
        v.skipReason = 'secure_file_priv 未放行（MySQL 8 默认 NULL）→ 本套件未执行任何断言';
      }
      return v;
    },
  },
  {
    id: 'file-write',
    title: 'fileWrite 真闭环（文件系统侧断言）',
    needs: ['secure_file_priv'],
    optional: true,
    // 与 fileRead 同一套自愈路径：宿主没放行 → 隔离沙箱重试（实测沙箱内真跑 PASS）。
    run: async () => {
      const r1 = await run('node', ['e2e/fileops/exploit-file-write.e2e.mjs'], { ...envDb, PENTEST_LAB_PORT: String(PORT_BASE + 3) });
      if (!/\[SKIP\]/.test(r1.out)) return r1;
      const r2 = await run('python', ['e2e/run-with-sandbox.py', 'e2e/fileops/exploit-file-write.e2e.mjs'], {}, 600000);
      return { ...r2, out: `${r1.out}\n—— 宿主未放行，改用隔离沙箱重试 ——\n${r2.out}` };
    },
    assert: (out) => {
      const tail = out.includes('改用隔离沙箱重试') ? out.split('改用隔离沙箱重试 ——').pop() : out;
      const viaSandbox = tail !== out;
      const passed = /\[PASS\] fileWrite/.test(tail);
      const skipped = /\[SKIP\]/.test(tail);
      const landed = /文件存在=true/.test(tail);
      // [SKIP-FIX 2026-09-19] 同 fileRead：只跳过就报 SKIP，不再冒充通过。
      const v = {
        facts: { PASS: passed, SKIP: skipped, 文件落盘: landed, 方式: viaSandbox ? '隔离沙箱重试' : '宿主实例' },
        pass: passed || skipped,
        reason: passed ? null : skipped ? null : '文件未落盘或断言失败',
      };
      if (skipped && !passed) {
        v.skipped = true;
        v.skipReason = 'secure_file_priv 未放行（MySQL 8 默认 NULL）→ 本套件未执行任何断言';
      }
      return v;
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
    // [P0-FIX 2026-09-18] 原因必须按**实际缺失的依赖**生成。
    // 旧实现只在缺 mysql 时用真实原因，其余一律兜底成「secure_file_priv 未放行」——
    // 于是「红队靶场没起」会被报成「MySQL 8 默认 NULL」，排障方向直接被带偏
    // （本次全量验收实测：10 PASS / 0 FAIL，唯一的 SKIP 就被贴错原因）。
    const MISSING_REASONS = {
      mysql: () => pre.mysqlReason,
      secure_file_priv: () => 'secure_file_priv 未放行（MySQL 8 默认 NULL）',
      redteamLab: () => `红队评测靶场未常驻（127.0.0.1:${REDTEAM_PORT}）——先执行 npm run lab:redteam`,
    };
    const why = missing
      .map((n) => (MISSING_REASONS[n] ? MISSING_REASONS[n]() : `缺少依赖：${n}`))
      .join('；');
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
  // [SKIP-FIX 2026-09-19] 第三态：断言根本没执行就是 SKIP，不是 PASS。
  // 原实现 `pass: passed || skipped` 让 fileRead / fileWrite 在 secure_file_priv=NULL 时以
  // 「✅ PASS　PASS=false　SKIP=true」进报告并计入顶部「11 PASS」——一行断言都没跑却算通过，
  // 与本仓 e2e/run-all.mjs 自己那句「跳过的不算通过」相互矛盾。
  // optional 的原意保留：SKIP 不进 failed、不改退出码（环境常态不该让门禁红），
  // 但必须数在 SKIP 名下（本机现状：9 PASS / 2 SKIP，而不是 11 PASS / 0 SKIP）。
  const skippedOnly = verdict.skipped === true;
  // [DECISION-2026-09-22] 「沙箱起不来」的判定抽到 e2e/lib/suiteVerdict.mjs（可单测）。
  // 旧实现只匹配「栈顶在 mysql_sandbox.py 的 traceback」一种形态 —— 实测（见该模块单测）
  // 漏掉了另外两种，且它们恰是 CI 容器最常见的：
  //   ② 启动器自身 import 失败（缺模块 / python 版本不对）
  //   ③ 连 python 都没起来（无 traceback，只剩 [sandbox-run] 前缀 + 非零退出）
  // 漏检的后果是把「验证装置没起来」误判成 FAIL —— 正是 §G「把环境问题归给被测代码」的重演。
  // 口径（回答 TODO §Y 的待决策项）：**既不是 SKIP 也不是 FAIL，是 BLOCKED**。
  //   · 不该 SKIP：SKIP 不进 failed，等于让这项能力的覆盖静默归零 ——
  //     而「静默地没在做事」是本项目最贵的一类错（见 facts 假绿 / 空转门禁）。
  //   · 不该 FAIL：一条断言都没执行，记 FAIL 会把下一个人引去查产品代码。
  //   · BLOCKED 与 FAIL 一样进 failed、一样让门禁非零退出，区别只在标签 —— 不是放水。
  const cls = classifySuite(verdict, r.out, r.code);
  const status = cls.status;
  const reason = cls.reason;
  results.push({
    ...s,
    status,
    facts: skippedOnly ? { 原因: verdict.skipReason || '环境不满足，未执行断言' } : verdict.facts,
    reason: status === 'PASS' ? null : reason,
    code: r.code,
    out: r.out,
  });
  if (skippedOnly) {
    console.log(`SKIP  原因：${verdict.skipReason || '环境不满足，未执行断言'}`);
    continue;
  }
  // [DIAG-FIX 2026-09-19] 失败时必须把该套件的原始输出留在盘上。
  // 此前 assert() 只回传「事实数字」，报告里就只剩一行 `服务端单测 fail=1` —— 到底是哪一条用例
  // 失败，得自己再手跑一遍才知道；而实测恰恰是这么丢的：acceptance 里 1883 pass / 1 fail，
  // 单独连跑 4 次全绿，失败现场已经没了。**门禁留不下现场，就等于把偶发缺陷变成了不可查。**
  // [ENV-BLOCK] 现场保留范围从 FAIL 扩到 FAIL+BLOCKED：上面那次定性靠的就是这份 dump，
  // 少了它就只能看到一个查不出原因的红灯。
  const dumpPath = resolve(HERE, 'results', `last-failure-${s.id}.log`);
  if (status === 'FAIL' || status === 'BLOCKED') {
    try {
      mkdirSync(resolve(HERE, 'results'), { recursive: true });
      // [现场卫生 2026-09-20] dump 必须带时间戳：否则三天前那次失败的现场会被下一个人当成
      // "刚刚又红了一次"的证据。本轮就差点这么被骗——file-write 的现场是 20:04 那次全量
      // 跑留下的，之后 `--only=file-write` 连跑 3 次全绿，但文件一直躺在那儿没变。
      writeFileSync(
        dumpPath,
        `$ ${s.title}\n状态：${status}\n失败于 ${new Date().toISOString()}\n退出码：${r.code}\n\n${r.out}`,
        'utf8'
      );
      console.log(`${status}  → ${reason}\n        现场已存 ${relative(ROOT, dumpPath)}`);
      continue;
    } catch { /* 落盘失败不阻断门禁 */ }
  }
  // [现场卫生 2026-09-20] 本套件这次过了，就把它的旧现场删掉。
  // 留着比没有更坏：一份"看起来是最新"的失败日志会误导排查方向（而它对应的那次运行早已作废）。
  if (status === 'PASS') {
    try { if (existsSync(dumpPath)) rmSync(dumpPath); } catch { /* 删不掉不影响门禁 */ }
  }
  console.log(`${status}  ${verdict.pass ? '' : `→ ${reason}`}`);
}

// ── 报告 ────────────────────────────────────────────────────────────────────
// BLOCKED 与 FAIL 必须分开计数：两者都让门禁不通过（都对），但**语义完全不同** ——
// FAIL = 断言没通过（被测代码有问题）；BLOCKED = 必需依赖缺失、套件根本没能执行。
// 此前终端汇总把两者合并成 "N FAIL"，与它上方刚打印的 `⛔ BLOCKED` 标签自相矛盾，
// 也与文档里写的 "6 BLOCKED" 不一致 —— 读的人会误以为有 6 项真的失败了。
// 报告文件里本来就带了 "(含 BLOCKED)" 限定词，终端那行漏了，现统一为分列。
const blocked = results.filter((r) => r.status === 'BLOCKED');
const realFailed = results.filter((r) => r.status === 'FAIL');
const failed = [...realFailed, ...blocked]; // 供退出码使用：两类都算不通过
const skipped = results.filter((r) => r.status === 'SKIP');
const passed = results.filter((r) => r.status === 'PASS');

const tally = () =>
  `${passed.length} PASS / ${blocked.length} BLOCKED / ${realFailed.length} FAIL / ${skipped.length} SKIP`;

const badge = { PASS: '✅ PASS', SKIP: '⏭ SKIP', BLOCKED: '⛔ BLOCKED', FAIL: '❌ FAIL' };
const row = (r) =>
  `| ${badge[r.status]} | ${r.title} | ` +
  `${Object.entries(r.facts || {}).map(([k, v]) => `${k}=${v}`).join('　')} |`;

// 套件范围：判据是「几个套件真跑出了断言 / 一共注册几个」，**不是文件名**（文件名可以被改）。
// 起因是实测到的一次假绿：`--only=file-write` 定向跑验收时，报告被写进
// `acceptance-report.md`（全量报告的位置），内容只有一行「✅ PASS fileWrite 真闭环」
// 加汇总「1 PASS / 0 FAIL」—— 看着全绿，实际 12 个套件只跑了 1 个。
// 与 TODO §Q 同源：**结论看着正常，语义完全不同**。
const trulyRan = results.filter((r) => r.status === 'PASS' || r.status === 'FAIL').length;
const isFullRun = !ONLY && !SKIP_HEAVY;
const scopeNotes = [
  ONLY ? `定向 --only=${[...ONLY].join(',')}` : '',
  SKIP_HEAVY ? '--skip-heavy' : '',
].filter(Boolean);
const scopeLine =
  `> 套件范围：**${trulyRan}/${SUITES.length} 跑出断言**` +
  (scopeNotes.length ? `（${scopeNotes.join('、')}）` : '') +
  (trulyRan === SUITES.length && isFullRun
    ? '　｜　判定：**全量**'
    : '　｜　⚠️ **判定：不完整 —— 不得当作该代码版本的整体验收结论**');
// 版本凭证：dirty 时报告**不对应任何提交**，必须让人一眼看到，否则它入库后会被读成
// 「某版代码的验收结论」。注意 dirty 是「跑之前」采集的，不含本次运行写出的产物。
const versionLine = git.dirty.length
  ? `> 代码版本：\`${git.head}\`　⚠️ **工作区 dirty**（跑验收前有 ${git.dirty.length} 个未提交改动：` +
    `${git.dirty.slice(0, 3).join('、')}${git.dirty.length > 3 ? ' 等' : ''}）—— **本报告不对应任何提交**`
  : `> 代码版本：\`${git.head}\`（工作区 clean）`;

const md = [
  isFullRun ? '# 全方位验收门禁报告' : '# 全方位验收门禁报告（⛔ 非全量运行）',
  '',
  `> 生成：${new Date().toISOString()}　｜　执行器：\`node e2e/acceptance.mjs\`　｜　Node ${process.version}`,
  versionLine,
  scopeLine,
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

// 只有**真全量**运行才写这份入库证据文件。定向 / 跳过 heavy 的写到 .partial.md ——
// 否则一次 `--only` 就会把库里那份全量结论覆盖掉（实测发生过，见上）。
mkdirSync(resolve(HERE, 'results'), { recursive: true });
const reportPath = resolve(HERE, 'results', isFullRun ? 'acceptance-report.md' : 'acceptance-report.partial.md');
writeFileSync(reportPath, md);

console.log('\n═══ 汇总 ═══');
for (const r of results) {
  console.log(
    `${r.status.padEnd(5)} ${r.title}　${Object.entries(r.facts || {}).map(([k, v]) => `${k}=${v}`).join(' ')}`
  );
}
// [WIRE-FIX 2026-09-19] 用 tally()。上一批提交（381afdb）写好了 tally() 却没接上调用点，
// 于是终端仍输出合并版「N FAIL」—— 与它自己上方刚打的 ⛔ BLOCKED 标签依旧矛盾，
// 也就是那条"BLOCKED 与 FAIL 分列"的修复实际没生效。e2e/acceptance.mjs 当时在 eslint 的 ignores
// 里（该目录级 ignore 已于 2026-09-19 撤掉），所以 `tally is assigned but never used` 这条 error 谁也没看见。
console.log(`\n${tally()}`);
console.log(`套件范围：${trulyRan}/${SUITES.length} 跑出断言${isFullRun ? '' : '（**非全量**，未覆盖全量报告）'}`);
console.log(`报告：${relative(ROOT, reportPath)}`);
process.exit(failed.length ? 1 : 0);
