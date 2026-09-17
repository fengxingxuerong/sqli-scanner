#!/usr/bin/env node
// ============================================================================
// e2e/one-click/one-click-scan.e2e.mjs —— 一键扫描端到端验收
// ============================================================================
// 存在理由：`scripts/one-click-scan.mjs` 是交付主入口（一条命令 → 全套结构化报告），
// 此前**零 e2e 覆盖**。「一键出报告」是承诺，必须用外部可观测事实来证明：
// 真进程退出码 + 真文件落盘 + manifest 字段完整性，而不是读代码推断。
//
// 两项设计约束：
//   ① 被测对象是**独立子进程**（spawn scripts/one-click-scan.mjs），不是 import 内部函数——
//      只有真进程才能验证退出码语义、环境变量策略（SSRF 放行）与落盘副作用；
//   ② 靶场在**本进程内**起（e2e/real-world-lab，PGlite 真实 PostgreSQL），零外部依赖，
//      不需要 Docker / 外部 MySQL，可在 CI 直接跑。
//
// 覆盖矩阵：
//   ① 主路径  注入目标 → 5 格式 + manifest 全落盘、退出码 2、交付五要素字段齐全
//   ② 格式矩阵 HTML/Markdown/SARIF/CSV 四侧都承载「受影响参数 + 漏洞类型」
//   ③ 退出码  安全目标 → 0（防误报）；发现高危 → 2
//   ④ 参数    POST JSON body / -r 请求文件导入 / --formats 子集 + --quiet
//   ⑤ 边界    缺目标 → 1；非法 --formats → 1
//   ⑥ 安全    SSRF 默认拒内网（不发包）；--scope 越界拒绝（发包前拦截）
//
// 用法：node e2e/one-click/one-click-scan.e2e.mjs
// ============================================================================

import { spawn } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync, existsSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { once } from 'node:events';
import { createRealLabApp } from '../real-world-lab/lab-app.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '../..');
const CLI = resolve(ROOT, 'scripts/one-click-scan.mjs');
const PORT = Number(process.env.ONE_CLICK_LAB_PORT) || 8240;
const BASE = `http://127.0.0.1:${PORT}`;
const SCAN_TIMEOUT_MS = 240_000;

let pass = 0;
let fail = 0;
const failures = [];
function check(name, cond, detail) {
  if (cond) {
    pass++;
    console.log(`  ✓ ${name}`);
  } else {
    fail++;
    failures.push(`${name}${detail ? `（${detail}）` : ''}`);
    console.log(`  ✗ ${name}${detail ? `（${detail}）` : ''}`);
  }
}

const TMP = mkdtempSync(join(tmpdir(), 'oc-e2e-'));
const cleanupDirs = [TMP];
function newOutDir(tag) {
  const d = join(TMP, `out-${tag}-${Math.random().toString(36).slice(2, 8)}`);
  cleanupDirs.push(d);
  return d;
}

/**
 * 以独立子进程跑一键脚本（真退出码 / 真落盘）。
 *
 * [必须异步] 靶场就跑在本进程里，若用 spawnSync 会**同步阻塞事件循环**——父进程停止响应
 * HTTP，扫描子进程的每个请求都等不到回包，只能一路挂到超时（实测 status=null 且无输出）。
 * 这是「父进程既是靶场又是驱动」拓扑下的固有陷阱，不是脚本 bug。
 */
function runOneClick(args, opts = {}) {
  return new Promise((done) => {
    const outDir = opts.outDir || newOutDir(opts.tag || 'x');
    const env = { ...process.env, SSRF_ALLOW_PRIVATE: '1', ...(opts.env || {}) };
    // 显式删除才能验证「SSRF 默认拒内网」——留空字符串不等于未设置
    if (opts.noSsrf) delete env.SSRF_ALLOW_PRIVATE;
    const child = spawn(process.execPath, [CLI, ...args, '--out', outDir], { cwd: ROOT, env });
    let stdout = '';
    let stderr = '';
    const timer = setTimeout(() => child.kill(), opts.timeoutMs || SCAN_TIMEOUT_MS);
    child.stdout.on('data', (d) => (stdout += d.toString('utf8')));
    child.stderr.on('data', (d) => (stderr += d.toString('utf8')));
    child.on('close', (code, signal) => {
      clearTimeout(timer);
      done({ status: code, signal, stdout, stderr, outDir });
    });
    child.on('error', (e) => {
      clearTimeout(timer);
      done({ status: null, error: e.message, stdout, stderr, outDir });
    });
  });
}

const has = (dir, f) => existsSync(join(dir, f));
const readJson = (dir, f) => JSON.parse(readFileSync(join(dir, f), 'utf8'));
const listFiles = (dir) => (existsSync(dir) ? readdirSync(dir) : []);

async function main() {
  console.log('═══ 一键扫描 e2e（真实 PGlite 靶场 + 独立子进程）═══\n');
  console.log(`靶场：${BASE}\n被测：${CLI}\n`);

  const app = await createRealLabApp();
  const server = app.listen(PORT, '127.0.0.1');
  await once(server, 'listening');

  try {
    // ── ① 主路径：注入目标 ────────────────────────────────────────────────
    console.log('① 主路径（GET 注入点，5 格式 + manifest）');
    const c1 = await runOneClick(['-u', `${BASE}/items?cat=1`, '--scope', '127.0.0.1', '--formats', 'html,json,markdown,sarif,csv', '--no-ledger'], { tag: 'main' });
    check('退出码 2（发现 High/Critical，可作 CI 门禁）', c1.status === 2, `status=${c1.status}`);
    const wantFiles = ['report.html', 'report.json', 'report.md', 'report.sarif', 'report.csv', 'manifest.json'];
    check('6 个文件全部真实落盘', wantFiles.every((f) => has(c1.outDir, f)), listFiles(c1.outDir).join(','));
    check('目录内无多余文件', listFiles(c1.outDir).length === wantFiles.length, listFiles(c1.outDir).join(','));

    const m1 = readJson(c1.outDir, 'manifest.json');
    check('manifest 风险等级 High', m1.riskLevel === 'High', `risk=${m1.riskLevel}`);
    check('manifest 数据库 PostgreSQL', m1.dbms === 'PostgreSQL', `dbms=${m1.dbms}`);
    check('manifest 声明授权范围', /范围/.test(m1.scope || ''), `scope=${m1.scope}`);
    check('manifest findings 非空', Array.isArray(m1.findings) && m1.findings.length > 0, `n=${m1.findings?.length}`);
    check('manifest 记录扫描耗时', typeof m1.durationMs === 'number' && m1.durationMs > 0);

    // —— 交付五要素（用户验收口径：漏洞类型/风险等级/受影响参数/利用证明/修复建议）——
    const f0 = m1.findings[0];
    check('五要素·漏洞类型：含 CWE 与规范化类型名', !!f0.vulnType?.cwe && !!f0.vulnType?.nameZh, JSON.stringify(f0.vulnType || null));
    check('五要素·风险等级：riskLevel + CVSS 分值', !!f0.riskLevel && typeof f0.cvss?.score === 'number', `${f0.riskLevel}/${f0.cvss?.score}`);
    check('五要素·受影响参数：参数名 + 位置', f0.affectedParam === 'cat' && f0.affectedLocation === 'url', `${f0.affectedParam}/${f0.affectedLocation}`);
    check('五要素·利用证明：可复跑 curl', typeof f0.poc?.curl === 'string' && f0.poc.curl.startsWith('curl'), (f0.poc?.curl || '').slice(0, 60));
    check('五要素·受影响请求：方法 + URL', /^GET http:\/\//.test(f0.affectedRequest || ''), f0.affectedRequest);

    // ── ② 格式矩阵：四侧都承载新增交付字段 ────────────────────────────────
    console.log('\n② 格式矩阵（HTML/Markdown/SARIF/CSV 四侧字段一致性）');
    const html = readFileSync(join(c1.outDir, 'report.html'), 'utf8');
    check('HTML：表头含受影响参数/漏洞类型', html.includes('<th>受影响参数</th>') && html.includes('<th>漏洞类型</th>'));
    check('HTML：单元格真实渲染参数名 + CWE', /cat · URL 查询参数/.test(html) && /CWE-89/.test(html));
    const md = readFileSync(join(c1.outDir, 'report.md'), 'utf8');
    check('Markdown：漏洞表头 8 列', /\| 注入点 \| 受影响参数 \| 漏洞类型 \| 技术 \| 数据库 \| 风险 \| CVSS \| 说明 \|/.test(md));
    check('Markdown：PoC 标题带参数名', /注入点 \w+（参数 cat）/.test(md));
    const csv = readFileSync(join(c1.outDir, 'report.csv'), 'utf8').replace(/^\uFEFF/, '');
    check('CSV：表头含受影响参数/CWE/OWASP/受影响请求', /^漏洞ID,注入点,受影响参数,漏洞类型,CWE,OWASP,技术,数据库,风险,CVSS,受影响请求,修复建议,说明/.test(csv));
    const sarif = readJson(c1.outDir, 'report.sarif');
    const rule = sarif.runs?.[0]?.tool?.driver?.rules?.[0];
    check('SARIF：rule 带 CWE/OWASP 属性', rule?.properties?.cwe === 'CWE-89' && rule?.properties?.owasp === 'A03:2021-Injection', JSON.stringify(rule?.properties || null));
    const res0 = sarif.runs?.[0]?.results?.[0];
    check('SARIF：result 带受影响参数与类型', res0?.properties?.affectedParam === 'cat' && !!res0?.properties?.vulnType, JSON.stringify(res0?.properties || null));

    // ── ③ 退出码：安全目标 → 0 ────────────────────────────────────────────
    console.log('\n③ 退出码语义（安全目标不得误报）');
    const c2 = await runOneClick(['-u', `${BASE}/blog?id=1`, '--scope', '127.0.0.1', '--formats', 'json', '--no-ledger'], { tag: 'safe' });
    check('安全目标 /blog：退出码 0', c2.status === 0, `status=${c2.status}`);
    const m2 = readJson(c2.outDir, 'manifest.json');
    check('安全目标：0 检出（无误报）', m2.findings.length === 0, `findings=${m2.findings.length}`);

    // ── ④ 参数矩阵 ────────────────────────────────────────────────────────
    console.log('\n④ 参数矩阵（POST JSON / -r 导入 / 格式子集 + quiet）');
    const c3 = await runOneClick(['-u', `${BASE}/api/item`, '--method', 'POST', '--body', '{"id":"1"}', '--scope', '127.0.0.1', '--formats', 'json', '--quiet', '--no-ledger'], { tag: 'post' });
    check('POST JSON body：退出码 2（检出）', c3.status === 2, `status=${c3.status}`);
    check('--quiet：仍产出 report.json + manifest', has(c3.outDir, 'report.json') && has(c3.outDir, 'manifest.json'));
    check('--formats json：仅 2 个文件（不产出 html/md）', listFiles(c3.outDir).length === 2, listFiles(c3.outDir).join(','));

    const reqFile = join(TMP, 'req.txt');
    writeFileSync(reqFile, `GET /items?cat=1 HTTP/1.1\r\nHost: 127.0.0.1:${PORT}\r\nUser-Agent: oc-e2e\r\n\r\n`, 'utf8');
    const c4 = await runOneClick(['-r', reqFile, '--scope', '127.0.0.1', '--formats', 'json', '--no-ledger'], { tag: 'reqfile' });
    check('-r 请求文件导入：退出码 2（检出）', c4.status === 2, `status=${c4.status}`);
    check('-r 导入：受影响参数仍是 cat', readJson(c4.outDir, 'manifest.json').findings.some((f) => f.affectedParam === 'cat'));

    // ── ⑤ 边界 ────────────────────────────────────────────────────────────
    console.log('\n⑤ 边界（缺目标 / 非法格式）');
    const c5 = await runOneClick([], { tag: 'noarg' });
    check('缺目标：退出码 1 且提示用法', c5.status === 1 && /缺少目标/.test(c5.stdout + c5.stderr), `status=${c5.status}`);
    const c6 = await runOneClick(['-u', `${BASE}/items?cat=1`, '--formats', 'xml,pdf'], { tag: 'badfmt' });
    check('非法 --formats：退出码 1 且列出支持格式', c6.status === 1 && /不支持的格式/.test(c6.stdout + c6.stderr), `status=${c6.status}`);

    // ── ⑥ 安全边界 ────────────────────────────────────────────────────────
    // 口径说明（server/src/core/http/egressGuard.js 的分层策略，勿简化为「默认拒内网」）：
    //   · 默认（本机 CLI 场景）**放行**回环/私网——本机靶场与内部授权目标是设计主场景；
    //   · SSRF_STRICT=1（或 HOST 指向非回环，即引擎对外暴露）才追加拒绝回环/私网/ULA；
    //   · 基础层（0.0.0.0/8、169.254/16 含云元数据、组播/保留/文档段）**无条件拒绝**，
    //     连 SSRF_ALLOW_PRIVATE=1 都盖不住。
    // 故此处按「严格层」与「硬底线」两层分别验证。
    console.log('\n⑥ 安全边界（严格层拒内网 / 硬底线拒云元数据 / scope 越界拦截）');
    const c7 = await runOneClick(['-u', `${BASE}/items?cat=1`, '--formats', 'json', '--no-ledger'], {
      tag: 'ssrf',
      noSsrf: true,
      env: { SSRF_STRICT: '1' },
    });
    const ssrfVulns = has(c7.outDir, 'report.json') ? readJson(c7.outDir, 'report.json').vulns?.length ?? 0 : 0;
    check('SSRF_STRICT=1：回环目标被拒（未检出）', ssrfVulns === 0, `vulns=${ssrfVulns} status=${c7.status}`);

    const c9 = await runOneClick(
      ['-u', 'http://169.254.169.254/latest/meta-data/', '--formats', 'json', '--no-ledger', '--timeout', '25000'],
      { tag: 'meta' }
    );
    const metaVulns = has(c9.outDir, 'report.json') ? readJson(c9.outDir, 'report.json').vulns?.length ?? 0 : 0;
    check('云元数据地址无条件拒绝（SSRF_ALLOW_PRIVATE=1 也盖不住）', metaVulns === 0, `vulns=${metaVulns} status=${c9.status}`);

    const c8 = await runOneClick(['-u', `${BASE}/items?cat=1`, '--scope', 'example.com', '--formats', 'json', '--no-ledger'], { tag: 'scope' });
    check('--scope 越界：退出码 1（发包前拦截）', c8.status === 1, `status=${c8.status}`);
    check('--scope 越界：不产出报告文件', !has(c8.outDir, 'report.json'), listFiles(c8.outDir).join(','));
  } finally {
    server.close();
    for (const d of cleanupDirs) { try { rmSync(d, { recursive: true, force: true }); } catch { /* 清理失败不影响结论 */ } }
  }

  console.log(`\n═══ 结果：${pass} PASS / ${fail} FAIL ═══`);
  if (failures.length) for (const f of failures) console.log(`  ✗ ${f}`);
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(`\n[FATAL] ${e?.stack || e?.message || e}`);
  process.exit(1);
});
