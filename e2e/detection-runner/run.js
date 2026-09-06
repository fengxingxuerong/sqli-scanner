// e2e/detection-runner/run.js
// ============================================================================
// 数据驱动检测测试运行器（Data-Driven Detection Test Runner）
//
// 用法：npm run test:detection（或 node e2e/detection-runner/run.js）
//
// 流程：
//   1. 扫描 e2e/fixtures/ 目录，加载所有 .json 场景文件
//   2. 启动目标靶场服务器（mock lab / safe lab / second-order lab）
//   3. 逐场景驱动 ScanManager 真实扫描
//   4. 对比 golden expected（检出技术 / 请求数 / 提取数据）
//   5. 生成 results/detection-report.md + results/detection-report.json
//
// 判定：
//   - expected.vulnerable=true 且 must 技术全命中 → PASS
//   - expected.vulnerable=false 且检出数=0 → PASS
//   - requestCount.max 超限 → WARN（不 FAIL，回归监控用）
//   - extracted 字段不匹配 → FAIL
//   - skip=true 的场景 → SKIP（不计入失败）
// ============================================================================

import { readFileSync, readdirSync, mkdirSync, writeFileSync, statSync } from 'node:fs';
import { dirname, resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = resolve(HERE, '../fixtures');
const RESULTS_DIR = resolve(HERE, 'results');
const MOCK_PORT = Number(process.env.MOCK_LAB_PORT) || 8123;
const SAFE_PORT = Number(process.env.SAFE_LAB_PORT) || 8124;
const SO_PORT = Number(process.env.SO_LAB_PORT) || 8125;
const SCENARIO_TIMEOUT_MS = 90_000;

// —— 基线配置（fixture config 覆盖此基线）——
const baseConfig = {
  concurrency: 4,
  ratePerSec: 0,
  retry: 0,
  timeoutMs: 12_000,
  enableExtract: false,
};

function fmtMs(ms) {
  return ms >= 1000 ? `${(ms / 1000).toFixed(1)}s` : `${ms}ms`;
}

// —— 加载 fixture 文件 ——
function loadFixtures() {
  const fixtures = [];
  function walk(dir) {
    for (const entry of readdirSync(dir)) {
      const full = join(dir, entry);
      const stat = statSync(full);
      if (stat.isDirectory()) {
        walk(full);
      } else if (entry.endsWith('.json')) {
        try {
          const data = JSON.parse(readFileSync(full, 'utf8'));
          fixtures.push({ ...data, _file: full });
        } catch (e) {
          console.error(`[runner] 无法加载 fixture ${full}: ${e.message}`);
        }
      }
    }
  }
  if (statSync(FIXTURES_DIR)) walk(FIXTURES_DIR);
  return fixtures;
}

// —— 构建 URL ——
function buildUrl(fixture, baseUrl) {
  const t = fixture.target;
  if (t.params) {
    const qs = Object.entries(t.params)
      .map(([k, v]) => `${k}=${encodeURIComponent(v)}`)
      .join('&');
    return `${baseUrl}/${t.endpoint}?${qs}`;
  }
  return `${baseUrl}/${t.endpoint}?${encodeURIComponent(t.param)}=${encodeURIComponent(t.value)}`;
}

// —— 驱动扫描 ——
// 使用 lab server 的 stats.total 追踪请求数（report 对象无 requests 字段）
async function runScan(sm, fixture, mockBase, safeBase, soBase, labs) {
  const t = fixture.target;
  const mergedConfig = { ...baseConfig, ...fixture.config };
  const startedAt = Date.now();

  // 选择对应靶场并重置计数
  let lab;
  if (t.type === 'mock') {
    lab = labs.mock;
    lab.resetStats();
  } else if (t.type === 'safe') {
    lab = labs.safe;
    lab.resetStats();
  } else if (t.type === 'second-order') {
    lab = labs.so;
    lab.resetStats();
    // 二阶注入需要先重置存储
    try {
      await fetch(`${soBase}/reset`);
    } catch { /* ignore */ }
  }

  let scanTarget;
  if (t.type === 'mock') {
    scanTarget = { url: buildUrl(fixture, mockBase), config: mergedConfig };
  } else if (t.type === 'safe') {
    scanTarget = { url: buildUrl(fixture, safeBase), config: mergedConfig };
  } else if (t.type === 'second-order') {
    // 二阶注入：目标 URL 是含 POST 表单的页面，config 中 secondOrder.enabled + triggerUrls 驱动检测
    scanTarget = { url: t.url || `${soBase}/store`, config: mergedConfig };
  } else {
    return { status: 'error', vulns: [], elapsedMs: 0, requestCount: 0, error: `unknown target type: ${t.type}` };
  }

  const scanId = await sm.start(scanTarget);
  for (;;) {
    const s = sm.scans.get(scanId);
    if (s && (s.status === 'completed' || s.status === 'error')) break;
    if (Date.now() - startedAt > SCENARIO_TIMEOUT_MS) {
      sm.stop(scanId).catch(() => {});
      return { status: 'timeout', vulns: [], elapsedMs: Date.now() - startedAt, requestCount: lab.stats.total, data: null };
    }
    await new Promise((r) => setTimeout(r, 20));
  }
  const report = sm.getReport(scanId) || { vulns: [] };
  return {
    status: sm.scans.get(scanId)?.status || 'unknown',
    vulns: report.vulns || [],
    data: report.data ?? null,
    requestCount: lab.stats.total,
    elapsedMs: Date.now() - startedAt,
  };
}

// —— Golden output 对比 ——
function compareGolden(fixture, result, requestCount) {
  const exp = fixture.expected;
  const found = new Set(result.vulns.map((v) => v.technique));
  const checks = [];
  let pass = true;

  // 1. vulnerable 布尔匹配
  if (exp.vulnerable === true) {
    const ok = result.vulns.length > 0;
    checks.push({ name: 'vulnerable=true', ok, detail: `检出 ${result.vulns.length} 个漏洞` });
    if (!ok) pass = false;
  } else if (exp.vulnerable === false) {
    const ok = result.vulns.length === 0;
    checks.push({ name: 'vulnerable=false', ok, detail: `检出 ${result.vulns.length} 个漏洞（期望 0）` });
    if (!ok) pass = false;
  }

  // 2. must 技术全命中
  if (exp.techniques?.must?.length) {
    const mustMiss = exp.techniques.must.filter((t) => !found.has(t));
    const ok = mustMiss.length === 0;
    checks.push({
      name: `must=[${exp.techniques.must.join(',')}]`,
      ok,
      detail: ok ? `全部命中` : `未命中: ${mustMiss.join(',')}`,
    });
    if (!ok) pass = false;
  }

  // 3. nice 技术记录
  if (exp.techniques?.nice?.length) {
    const niceHit = exp.techniques.nice.filter((t) => found.has(t));
    checks.push({
      name: `nice=[${exp.techniques.nice.join(',')}]`,
      ok: true,
      detail: `命中: ${niceHit.join(',') || '无'}（不计失败）`,
    });
  }

  // 4. requestCount 上限（回归监控）
  if (exp.requestCount?.max) {
    const ok = requestCount <= exp.requestCount.max;
    checks.push({
      name: `requests<=${exp.requestCount.max}`,
      ok,
      detail: `实际 ${requestCount}${ok ? '' : ' ⚠超限'}`,
      severity: ok ? 'pass' : 'warn',
    });
    // 请求数超限只 WARN 不 FAIL
  }

  // 5. 提取数据验证
  if (exp.extracted) {
    const d = result.data;
    if (exp.extracted.databases === 'non-empty') {
      const ok = d && Array.isArray(d.databases) && d.databases.length > 0;
      checks.push({ name: 'extracted.databases non-empty', ok, detail: ok ? `提取 ${d.databases.length} 个库` : '未提取到数据库' });
      if (!ok) pass = false;
    } else if (exp.extracted.databases === 'empty') {
      const ok = !d || !d.databases || d.databases.length === 0;
      checks.push({ name: 'extracted.databases empty', ok, detail: ok ? '无提取（正确）' : `意外提取 ${d?.databases?.length || 0} 个库` });
      if (!ok) pass = false;
    }
    if (exp.extracted.tables === 'non-empty') {
      const ok = d && typeof d.tables === 'object' && d.tables != null && Object.keys(d.tables).length > 0;
      checks.push({ name: 'extracted.tables non-empty', ok, detail: ok ? `提取 ${Object.keys(d.tables).length} 个库的表` : '未提取到表' });
      if (!ok) pass = false;
    } else if (exp.extracted.tables === 'empty') {
      const ok = !d || !d.tables || Object.keys(d.tables || {}).length === 0;
      checks.push({ name: 'extracted.tables empty', ok, detail: ok ? '无提取（正确）' : `意外提取表` });
      if (!ok) pass = false;
    }
    if (exp.extracted.databaseContains) {
      const ok = d && Array.isArray(d.databases) && d.databases.some((db) => typeof db === 'string' && db.includes(exp.extracted.databaseContains));
      checks.push({ name: `extracted.databases contains "${exp.extracted.databaseContains}"`, ok, detail: ok ? '找到' : '未找到' });
      if (!ok) pass = false;
    }
    if (exp.extracted.tableContains) {
      const ok = d && typeof d.tables === 'object' && d.tables != null &&
        Object.values(d.tables).some((tables) => Array.isArray(tables) && tables.some((t) => typeof t === 'string' && t.includes(exp.extracted.tableContains)));
      checks.push({ name: `extracted.tables contains "${exp.extracted.tableContains}"`, ok, detail: ok ? '找到' : '未找到' });
      if (!ok) pass = false;
    }
  }

  return { pass, checks, found: [...found] };
}

// —— 生成报告 ——
function generateReport(rows, stats) {
  const now = new Date().toISOString();
  const lines = [
    '# 数据驱动检测测试报告（Detection Test Report）',
    '',
    `> 生成时间：${now}　｜　运行器：\`npm run test:detection\``,
    `> 场景总数：${rows.length}　｜　PASS：${stats.pass}　｜　FAIL：${stats.fail}　｜　SKIP：${stats.skip}　｜　WARN：${stats.warn}`,
    '',
    '## 召回场景（vulnerable=true，must 技术须全命中）',
    '',
    '| 场景 | 描述 | 检出 | must 命中 | 请求数 | 检查项 | 耗时 | 结果 |',
    '|---|---|---|---|---|---|---|---|',
  ];

  for (const r of rows) {
    if (r.category === 'recall') {
      const checkSummary = r.checks.map((c) => `${c.ok ? '✓' : '✗'}${c.name}`).join(' ');
      lines.push(
        `| ${r.name} | ${r.description} | ${r.found.join(', ') || '-'} | ` +
        `${r.checks.filter((c) => c.name.startsWith('must')).map((c) => c.detail).join('; ') || '-'} | ` +
        `${r.requestCount} | ${checkSummary} | ${fmtMs(r.elapsedMs)} | ${r.result} |`
      );
    }
  }

  lines.push('', '## 假阳性场景（vulnerable=false，检出数须=0）', '',
    '| 场景 | 描述 | 检出数 | 请求数 | 耗时 | 结果 |', '|---|---|---|---|---|---|');
  for (const r of rows) {
    if (r.category === 'false-positive') {
      lines.push(`| ${r.name} | ${r.description} | ${r.vulnCount} | ${r.requestCount} | ${fmtMs(r.elapsedMs)} | ${r.result} |`);
    }
  }

  lines.push('', '## 提取验证场景（golden output 对比）', '',
    '| 场景 | 描述 | 检出 | 提取检查 | 请求数 | 耗时 | 结果 |', '|---|---|---|---|---|---|---|');
  for (const r of rows) {
    if (r.category === 'extraction') {
      const extractChecks = r.checks.filter((c) => c.name.startsWith('extracted')).map((c) => `${c.ok ? '✓' : '✗'}${c.name.replace('extracted.', '')}`).join(' ');
      lines.push(`| ${r.name} | ${r.description} | ${r.found.join(', ') || '-'} | ${extractChecks || '-'} | ${r.requestCount} | ${fmtMs(r.elapsedMs)} | ${r.result} |`);
    }
  }

  lines.push('', '## 二阶注入场景', '',
    '| 场景 | 描述 | 检出 | must 命中 | 请求数 | 耗时 | 结果 |', '|---|---|---|---|---|---|---|');
  for (const r of rows) {
    if (r.category === 'second-order') {
      lines.push(`| ${r.name} | ${r.description} | ${r.found.join(', ') || '-'} | ${r.checks.filter((c) => c.name.startsWith('must')).map((c) => c.detail).join('; ') || '-'} | ${r.requestCount} | ${fmtMs(r.elapsedMs)} | ${r.result} |`);
    }
  }

  // 失败详情
  const failures = rows.filter((r) => r.result === 'FAIL');
  if (failures.length) {
    lines.push('', '## 失败详情', '');
    for (const f of failures) {
      lines.push(`### ${f.name}（${f.description}）`, '');
      for (const c of f.checks) {
        if (!c.ok) lines.push(`- **FAIL** ${c.name}: ${c.detail}`);
      }
      lines.push('');
    }
  }

  lines.push('', '---', '',
    `**场景文件**：\`e2e/fixtures/**/*.json\`　｜　**运行器**：\`e2e/detection-runner/run.js\``,
    `**添加新场景**：在 \`e2e/fixtures/<category>/\` 下新建 .json 文件，无需修改运行器代码`);

  return lines.join('\n');
}

// —— 主函数 ——
async function main() {
  const fixtures = loadFixtures();
  if (fixtures.length === 0) {
    console.error('[runner] 未找到 fixture 文件，请检查 e2e/fixtures/ 目录');
    process.exit(1);
  }
  console.log(`[runner] 加载 ${fixtures.length} 个 fixture 场景`);

  // 分类统计
  const byCategory = {};
  for (const f of fixtures) {
    const cat = f._file.split(/[/\\]/).slice(-2, -1)[0];
    byCategory[cat] = (byCategory[cat] || 0) + 1;
  }
  for (const [cat, count] of Object.entries(byCategory)) {
    console.log(`  ${cat}: ${count} 场景`);
  }

  // 启动靶场服务器
  const mockBase = `http://127.0.0.1:${MOCK_PORT}`;
  const safeBase = `http://127.0.0.1:${SAFE_PORT}`;
  const soBase = `http://127.0.0.1:${SO_PORT}`;

  const { createRecallLab } = await import('../recall-lab/lab-server.js');
  const { createSafeLab } = await import('../recall-lab/safe-lab-server.js');
  const { createSecondOrderLab } = await import('./second-order-lab.js');
  const { ScanManager } = await import('../../server/src/engine/ScanManager.js');

  const mockLab = createRecallLab();
  const safeLab = createSafeLab();
  const soLab = createSecondOrderLab();

  await Promise.all([
    new Promise((r) => mockLab.server.listen(MOCK_PORT, '127.0.0.1', r)),
    new Promise((r) => safeLab.server.listen(SAFE_PORT, '127.0.0.1', r)),
    new Promise((r) => soLab.server.listen(SO_PORT, '127.0.0.1', r)),
  ]);
  console.log(`[runner] 靶场已启动：mock=${mockBase} safe=${safeBase} second-order=${soBase}`);

  const rows = [];
  const stats = { pass: 0, fail: 0, skip: 0, warn: 0 };

  try {
    for (const fixture of fixtures) {
      const category = fixture._file.split(/[/\\]/).slice(-2, -1)[0];

      // skip 场景
      if (fixture.skip) {
        console.log(`[SKIP] ${fixture.name}（${fixture.description}）${fixture.skipReason ? ' — ' + fixture.skipReason : ''}`);
        stats.skip++;
        rows.push({
          name: fixture.name,
          description: fixture.description,
          category,
          result: 'SKIP',
          found: [],
          checks: [],
          requestCount: 0,
          elapsedMs: 0,
          vulnCount: 0,
        });
        continue;
      }

      const t0 = Date.now();
      try {
        const sm = new ScanManager({});
        const labs = { mock: mockLab, safe: safeLab, so: soLab };
        const out = await runScan(sm, fixture, mockBase, safeBase, soBase, labs);
        const requestCount = out.requestCount || 0;
        const comparison = compareGolden(fixture, out, requestCount);
        const hasWarn = comparison.checks.some((c) => c.severity === 'warn' && !c.ok);
        const result = comparison.pass ? (hasWarn ? 'WARN' : 'PASS') : 'FAIL';

        if (result === 'PASS') stats.pass++;
        else if (result === 'FAIL') stats.fail++;
        else if (result === 'WARN') { stats.warn++; stats.pass++; }

        const mark = result === 'PASS' ? 'PASS' : result === 'WARN' ? 'WARN' : 'FAIL';
        console.log(
          `[${mark}] ${fixture.name}（${fixture.description}）检出=[${comparison.found.join(',') || '-'}] ` +
          `请求=${requestCount} 耗时=${fmtMs(Date.now() - t0)}`
        );
        if (!comparison.pass) {
          for (const c of comparison.checks) {
            if (!c.ok) console.log(`       ↳ ${c.name}: ${c.detail}`);
          }
        }

        rows.push({
          name: fixture.name,
          description: fixture.description,
          category,
          result,
          found: comparison.found,
          checks: comparison.checks,
          requestCount,
          elapsedMs: Date.now() - t0,
          vulnCount: out.vulns.length,
        });
      } catch (e) {
        stats.fail++;
        console.log(`[FAIL] ${fixture.name}（${fixture.description}）异常: ${e.message}`);
        rows.push({
          name: fixture.name,
          description: fixture.description,
          category,
          result: 'FAIL',
          found: [],
          checks: [{ name: 'exception', ok: false, detail: e.message }],
          requestCount: 0,
          elapsedMs: Date.now() - t0,
          vulnCount: 0,
        });
      }
      // 场景间稍歇
      await new Promise((r) => setTimeout(r, 150));
    }
  } finally {
    mockLab.server.close();
    safeLab.server.close();
    soLab.server.close();
  }

  // 生成报告
  mkdirSync(RESULTS_DIR, { recursive: true });
  const md = generateReport(rows, stats);
  writeFileSync(resolve(RESULTS_DIR, 'detection-report.md'), md, 'utf8');
  writeFileSync(
    resolve(RESULTS_DIR, 'detection-report.json'),
    JSON.stringify({ generatedAt: new Date().toISOString(), stats, rows }, null, 2),
    'utf8'
  );
  console.log(`\n[runner] 报告已写入 e2e/detection-runner/results/detection-report.md`);
  console.log(`[runner] 统计：${stats.pass} PASS / ${stats.fail} FAIL / ${stats.skip} SKIP / ${stats.warn} WARN`);

  if (stats.fail > 0) {
    console.error('[runner] 存在失败场景，检测回归失败');
    process.exitCode = 1;
  }
}

main().catch((e) => {
  console.error('[runner] 运行异常：', e);
  process.exitCode = 1;
});
