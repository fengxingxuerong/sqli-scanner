// ============================================================================
// e2e/waf-lab/compare-real.e2e.mjs —— WAF 绕过 A/B 实验（真 MySQL 靶场版）
// ============================================================================
// 背景（2026-09-18 修复）：
//   原 compare.e2e.js 使用 lab-server-v2.js 的 /vuln 端点，而该端点实现是
//     app.get('/vuln', (req, r) => r.send(`row:${req.query.id}`));
//   —— 纯字符串拼接回显，**没有任何 SQL 执行**。因此：
//     · 加 ' 不报错   → error 型无信号
//     · union 即使穿过 WAF，回显也只是字面量 → 回显标记永不出现
//     · 响应内容恒由输入决定 → boolean 真/假页无差异
//   两侧检出率恒为 0，判据 detectRateB > detectRateA 从设计上不可能成立。
//   实测证据：`?id=1'` → 200 `row:1'`；`?id=1' and 1=1-- -` → 403（仅 WAF 拦）。
//
//   本版改为复用 e2e/real-mysql-lab/lab-app.js（mysql2 直连真 MySQL 的真注入点），
//   并把 WAF 规则以 preMiddleware 挂上去 —— 该参数本就是为此设计（见 lab-app.js 注释）。
//   靶子从「空壳回显」变为「真 SQL 执行」，判据才有意义。
//
// 连接：由 compare-real.run.py 在同一进程内起隔离 MySQL 沙箱（3308），
//       通过环境变量 MYSQL_HOST/PORT/USER/PASSWORD/DATABASE 传入。
// 用法：node e2e/waf-lab/compare-real.e2e.mjs    （需沙箱已起）
// ============================================================================
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import fs from 'node:fs';
import { createRequire } from 'node:module';
import { createMysqlLabApp } from '../real-mysql-lab/lab-app.js';
import { computeMetrics } from './metrics.js';
import { PROFILES } from './waf-profiles.js';

const _require = createRequire(new URL('../../server/package.json', import.meta.url));
const mysql = _require('mysql2/promise');

const HERE = path.dirname(fileURLToPath(import.meta.url));
const LAB_PORT = Number(process.env.WAF_LAB_PORT) || 8099;
const WAIT_TIMEOUT_MS = 180000;

// 目标：真 MySQL 的数值型注入点（union/error/boolean 全通道可用）
const TARGET = `http://127.0.0.1:${LAB_PORT}/num?id=1`;

// configB 的 tamper 组合：space2comment 是绕过本实验室空格锚定规则的关键；
// commentbeforeparentheses 绕过 extractvalue/updatexml 的 \s*\( 锚定；
// charencode 绕过 `--\s*$` 行尾注释规则。
// randomcase 会打乱回显标记大小写导致 union 检测失效，故不纳入。
const CONFIG_B_TAMPER = ['space2comment', 'commentbeforeparentheses', 'charencode'];

// 使用 modsecurity_crs profile（与 compare.e2e.js 保持一致，便于对比历史数据）
const PROFILE = PROFILES.find((p) => p.id === 'modsecurity_crs') || PROFILES[0];

function buildConfig(tamperOn) {
  const tamper = tamperOn
    ? { enabled: true, plugins: CONFIG_B_TAMPER, intensity: 'medium' }
    : { enabled: false, plugins: [], intensity: 'medium' };
  return {
    techniques: ['union', 'error', 'boolean'],
    dbms: 'MySQL',
    enableExtract: false,
    maxColumnsGuess: 3,
    ratePerSec: 20,
    concurrency: 4,
    timeoutMs: 8000,
    blindRobust: { enabled: false },
    wafEvasion: { randomUA: false, jitterMs: 0, obfuscate: false, tamper },
  };
}

/** WAF 中间件：命中规则即 403，并统计命中；非 /__ 路径才过规则。 */
function makeWafMiddleware(initialStats) {
  const stats = { total: 0, blocked: 0, passed: 0, byRule: {} };
  Object.assign(stats, initialStats);
  const mw = (req, res, next) => {
    if (req.path.startsWith('/__')) return next();
    const probe = JSON.stringify(req.query) + JSON.stringify(req.body || '');
    stats.total += 1;
    const hit = PROFILE.rules.find((r) => r.re.test(probe));
    if (hit) {
      stats.blocked += 1;
      stats.byRule[hit.id] = (stats.byRule[hit.id] || 0) + 1;
      return res.status(403).send(`<h1>403 Forbidden</h1><p>Rule: ${hit.id}</p>`);
    }
    stats.passed += 1;
    next();
  };
  mw.stats = stats;
  return mw;
}

function waitForScan(sm, scanId) {
  const start = Date.now();
  return new Promise((resolve) => {
    const tick = () => {
      const report = sm.getReport(scanId);
      if (report && (report.finishedAt || report.status === 'completed' || report.status === 'error')) {
        return resolve(report);
      }
      if (Date.now() - start > WAIT_TIMEOUT_MS) return resolve(report);
      setTimeout(tick, 200);
    };
    tick();
  });
}

async function main() {
  const MYSQL_CONF = {
    host: process.env.MYSQL_HOST || '127.0.0.1',
    port: Number(process.env.MYSQL_PORT) || 3308,
    user: process.env.MYSQL_USER || 'root',
    password: process.env.MYSQL_PASSWORD ?? '',
    database: process.env.MYSQL_DATABASE || 'sqli_lab',
    connectionLimit: 8,
  };

  // 起真 MySQL 连接池（证明沙箱可达；连不上会立刻显式失败，不静默降级）
  const pool = mysql.createPool(MYSQL_CONF);
  let chk;
  try {
    [chk] = await pool.query('SELECT VERSION() AS v');
  } catch (e) {
    // 明确前置失败：本脚本默认连 3308（隔离沙箱）。若直连运行而沙箱未起，
    // 裸 ECONNREFUSED 难以定位，这里给出可操作提示。
    console.error(
      `[waf-e2e-real] 无法连接 MySQL ${MYSQL_CONF.host}:${MYSQL_CONF.port} —— ${e.code || e.message}\n` +
      '  本脚本需要真 MySQL。两种跑法：\n' +
      '    ① 经沙箱（推荐）：python e2e/waf-lab/compare-real.run.py\n' +
      '       或 npm run e2e:sandbox e2e/waf-lab/compare-real.e2e.mjs\n' +
      '    ② 直连宿主：设 MYSQL_HOST/MYSQL_PORT/MYSQL_USER/MYSQL_PASSWORD 指向已有实例'
    );
    await pool.end().catch(() => {});
    process.exit(2);
  }
  console.log(`[waf-e2e-real] MySQL 已连通：${chk[0].v} @ ${MYSQL_CONF.host}:${MYSQL_CONF.port}/${MYSQL_CONF.database}`);
  const [rowChk] = await pool.query('SELECT COUNT(*) AS n FROM users');
  console.log(`[waf-e2e-real] 靶场表 users 行数=${rowChk[0].n}（>0 才说明 real-mysql-lab schema 就绪）`);
  if (Number(rowChk[0].n) <= 0) {
    throw new Error('users 表为空，real-mysql-lab schema 未初始化');
  }

  const waf = makeWafMiddleware({});
  const app = createMysqlLabApp(pool, waf);
  const server = app.listen(LAB_PORT);
  await new Promise((r) => {
    if (server.listening) return r();
    server.once('listening', r);
  });

  // 自检：确认靶子**真的可注入**（否则判据又是空转）
  const selfCheck = async (u) => {
    const r = await fetch(u);
    return { status: r.status, body: await r.text() };
  };
  const b1 = await selfCheck(`http://127.0.0.1:${LAB_PORT}/num?id=1`);
  const b2 = await selfCheck(`http://127.0.0.1:${LAB_PORT}/num?id=1%20union%20select%201,2,3,4,5,6,7,8`);
  console.log(`[waf-e2e-real] 自检 良性=${b1.status}（期望200）　union=${b2.status}（期望 200=未被WAF拦）`);
  if (b1.status !== 200) throw new Error(`良性请求未通过（${b1.status}），靶场异常`);

  const { pathToFileURL } = await import('node:url');
  const { ScanManager } = await import(
    pathToFileURL(path.resolve(HERE, '../../server/src/engine/ScanManager.js')).href
  );

  const sm = new ScanManager();

  /**
   * 口径对齐 metrics.js 注释：「检出率 = 被确认 vulnerable 的注入点数 / 总注入点数」。
   * 注意 vulns 是**按 technique 拆分**的（同一注入点 union+error+boolean 会出多条），
   * 直接取 vulns.length 当分子会得到「2/1 = 200%」这种荒谬值。
   * 故：分子 = 去重后的 pointId 数；分母 = report.points.length（真实注入点数）。
   * 同时保留 vulnCount（按技术计数）作为附加信息，不参与判据。
   */
  const summarize = (report, blockedReq, totalReq, byRule) => {
    const points = report?.points || [];
    const vulns = report?.vulns || [];
    const vulnPointIds = new Set(vulns.map((v) => v.pointId).filter(Boolean));
    return {
      totalPoints: points.length,
      detectedPoints: vulnPointIds.size,
      vulnCount: vulns.length,
      techniques: [...new Set(vulns.map((v) => v.technique))],
      blockedReq,
      totalReq,
      byRule,
    };
  };

  // —— configA：tamper 关 ——
  Object.assign(waf.stats, { total: 0, blocked: 0, passed: 0, byRule: {} });
  const reportA = await waitForScan(sm, await sm.start({ url: TARGET, config: buildConfig(false) }));
  const A = summarize(reportA, waf.stats.blocked, waf.stats.total, { ...waf.stats.byRule });

  // —— configB：tamper 开 ——
  Object.assign(waf.stats, { total: 0, blocked: 0, passed: 0, byRule: {} });
  const reportB = await waitForScan(sm, await sm.start({ url: TARGET, config: buildConfig(true) }));
  const B = summarize(reportB, waf.stats.blocked, waf.stats.total, { ...waf.stats.byRule });

  // 分母以两次扫描的注入点数取大者（同一目标应一致；不一致说明探测不稳定，如实暴露）
  const totalPoints = Math.max(A.totalPoints, B.totalPoints);

  const metrics = computeMetrics({
    totalPoints,
    detectedA: A.detectedPoints,
    detectedB: B.detectedPoints,
    blockedReqA: A.blockedReq,
    blockedReqB: B.blockedReq,
    totalReqA: A.totalReq,
    totalReqB: B.totalReq,
  });

  // ────────────────────────────────────────────────────────────────────────
  // 判据（2026-09-18 修订）
  // ────────────────────────────────────────────────────────────────────────
  // 旧判据 detectRateB > detectRateA 在本装置上**无区分度**：靶场只有一个注入点，
  // 且 error/boolean 通道在两种配置下都能打进 → 两侧恒 100%，触顶后比较不出差异。
  // 实测（2026-09-18）：configA 检出率 100%、configB 100% → 旧判据恒 NO。
  //
  // 真正要验证的是「tamper 是否绕过了 WAF」，故改用 WAF 侧指标：
  //   主判据 blockRateB < blockRateA —— tamper 生效后请求被拦的比例必须下降；
  //   辅判据 高危规则命中数下降 —— 942141(extractvalue)/942142(updatexml)/942180
  //          (information_schema) 这类「函数名 + \s*\( 锚定」的规则应被 tamper 绕开。
  // 实测：blockRate 70.7% → 45.7%；942141/942142 命中 26 次 → 0 次。
  // ────────────────────────────────────────────────────────────────────────
  const HIGH_RISK_RULES = ['crs_942141', 'crs_942142', 'crs_942180'];
  const sumRules = (byRule, ids) => ids.reduce((n, id) => n + (byRule[id] || 0), 0);
  const highRiskA = sumRules(A.byRule, HIGH_RISK_RULES);
  const highRiskB = sumRules(B.byRule, HIGH_RISK_RULES);

  const criterion1 = metrics.blockRateB < metrics.blockRateA;      // 拦截率下降
  const criterion2 = highRiskB < highRiskA;                        // 高危规则命中下降
  const pass = criterion1 && criterion2;

  const outDir = path.join(HERE, 'results');
  fs.mkdirSync(outDir, { recursive: true });
  const jsonPath = path.join(outDir, 'compare-real.json');
  const mdPath = path.join(outDir, 'compare-real.md');

  fs.writeFileSync(
    jsonPath,
    JSON.stringify(
      {
        meta: {
          target: TARGET,
          profile: PROFILE.id,
          mysql: chk[0].v,
          note: '真 MySQL 靶场（real-mysql-lab）+ WAF 中间件',
          caliber: '检出率=去重 pointId 数 / report.points.length（对齐 metrics.js 注释）',
        },
        metrics,
        criteria: {
          blockRateDrop: { value: criterion1, from: metrics.blockRateA, to: metrics.blockRateB },
          highRiskRuleDrop: { value: criterion2, from: highRiskA, to: highRiskB, rules: HIGH_RISK_RULES },
          passed: pass,
        },
        configA: { tamper: 'off', ...A },
        configB: { tamper: 'on', plugins: CONFIG_B_TAMPER, ...B },
      },
      null,
      2
    )
  );

  const md = [
    '# WAF 绕过 A/B 实验（真 MySQL 靶场）',
    '',
    `> 目标：${TARGET}`,
    `> 后端：真 MySQL ${chk[0].v}（隔离沙箱）＋ real-mysql-lab 真注入点`,
    `> WAF profile：${PROFILE.id}`,
    `> configB tamper：${CONFIG_B_TAMPER.join(', ')}`,
    '',
    '## 检出侧（靶子是否真被打进）',
    '',
    '| 配置 | 注入点 | 检出点 | 检出率 | 漏洞条目 | 命中技术 |',
    '|------|-------|--------|--------|---------|---------|',
    `| tamper 关 (configA) | ${totalPoints} | ${A.detectedPoints} | ${metrics.detectRateA}% | ${A.vulnCount} | ${A.techniques.join('/') || '-'} |`,
    `| tamper 开 (configB) | ${totalPoints} | ${B.detectedPoints} | ${metrics.detectRateB}% | ${B.vulnCount} | ${B.techniques.join('/') || '-'} |`,
    '',
    '## WAF 侧（tamper 是否真绕过）—— 主判据',
    '',
    '| 配置 | 总请求 | 被拦截 | 拦截率 | 高危规则命中 |',
    '|------|-------|--------|--------|-------------|',
    `| tamper 关 (configA) | ${A.totalReq} | ${A.blockedReq} | ${metrics.blockRateA}% | ${highRiskA} |`,
    `| tamper 开 (configB) | ${B.totalReq} | ${B.blockedReq} | ${metrics.blockRateB}% | ${highRiskB} |`,
    '',
    `**判据① 拦截率下降（${metrics.blockRateA}% → ${metrics.blockRateB}%）? ${criterion1 ? 'YES ✅' : 'NO ❌'}**`,
    `**判据② 高危规则命中下降（${highRiskA} → ${highRiskB}，规则 ${HIGH_RISK_RULES.join('/')}）? ${criterion2 ? 'YES ✅' : 'NO ❌'}**`,
    '',
    `**结论：${pass ? 'tamper 确已绕过 WAF ✅' : '未证实绕过 ❌'}**`,
    '',
    '> 口径说明：',
    '> · 检出率 = 去重 pointId 数 / report.points.length（对齐 metrics.js 注释）。',
    '> · 本装置单注入点且 error/boolean 双通道均可打进，检出率两侧触顶 100%，',
    '>   故**不作主判据**（旧版以此为判据，恒为 NO，属指标选择错误）。',
    '> · 漏洞条目按 technique 拆分，仅作附加信息。',
    '',
    `> configA 命中规则：${JSON.stringify(A.byRule)}`,
    `> configB 命中规则：${JSON.stringify(B.byRule)}`,
  ].join('\n');
  fs.writeFileSync(mdPath, md);

  console.log(md);
  console.log(`\n[waf-e2e-real] 产物已写入:\n  ${jsonPath}\n  ${mdPath}`);

  server.close();
  await pool.end();
  process.exit(pass ? 0 : 1);
}

main().catch((e) => {
  console.error('[waf-e2e-real] 失败:', e);
  process.exit(1);
});
