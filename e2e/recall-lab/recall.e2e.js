// ============================================================================
// recall.e2e.js —— 检测召回回归 runner（对标 sqlmap 的可回归检出率基线）
// 用法：npm run recall-e2e（或 node e2e/recall-lab/recall.e2e.js）
// 流程：同进程启动 recall-lab 靶场 → 逐场景驱动 ScanManager 真实 HTTP 扫描 →
//       断言 must 技术命中 → 产出 results/recall.md 矩阵（场景 × 技术 × 检出 + 请求数/耗时）
// 判定：must 全命中 exit 0；任一 must 未命中 exit 1（nice 仅记录不算失败）
// ============================================================================
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
const { createRecallLab } = await import('./lab-server.js');
const { buildTarget, sqljsAvailable, buildPgTarget, pgAvailable, buildMysqlTarget, mysqlAvailable } = await import('./real-lab-driver.js');
const { ScanManager } = await import('../../server/src/engine/ScanManager.js');

const HERE = dirname(fileURLToPath(import.meta.url));
const RESULTS_DIR = resolve(HERE, 'results');
const PORT = Number(process.env.PORT) || 8123;
const BASE = `http://127.0.0.1:${PORT}`;
// 单场景墙钟上限（检测轮询 + 引擎内部超时余量）
const SCENARIO_TIMEOUT_MS = 90_000;

// 场景清单：must=必须检出（否则 exit 1）；nice=记录不计失败（引擎能力边界观察项）
const SCENARIOS = [
  {
    name: 'num',
    desc: '数值型上下文（id=1，无引号）',
    url: `${BASE}/num?id=1`,
    config: { techniques: ['union', 'error', 'boolean'] },
    must: ['union', 'error', 'boolean'],
    nice: [],
  },
  {
    name: 'str',
    desc: "单引号字符串上下文（name='…'，需 ' 闭合）",
    url: `${BASE}/str?name=foo`,
    config: { techniques: ['union', 'error', 'boolean'] },
    must: ['boolean', 'error'],
    nice: ['union'],
  },
  {
    name: 'paren',
    desc: "括号包裹上下文（('…')，需 ') 闭合）",
    url: `${BASE}/paren?id=1`,
    config: { techniques: ['union', 'error', 'boolean'] },
    must: ['boolean'],
    nice: ['error', 'union'],
  },
  {
    name: 'orderby',
    desc: 'ORDER BY 位置注入（逗号型子句 payload，level=2）',
    url: `${BASE}/orderby?sort=id`,
    config: { techniques: ['boolean', 'time'], level: 2, timeBlindSleepSec: 1, timeThresholdMs: 800, timeBlindSamples: 3 },
    must: ['boolean'],
    nice: ['time'],
  },
  {
    name: 'bool',
    desc: '仅布尔差异（无回显/无报错/无延迟）',
    url: `${BASE}/bool?uid=1`,
    config: { techniques: ['boolean'] },
    must: ['boolean'],
    nice: [],
  },
  {
    name: 'time',
    desc: '仅时间通道（内容恒定，sleep 生效）',
    url: `${BASE}/time?tid=1`,
    config: { techniques: ['time'], timeBlindSleepSec: 1, timeThresholdMs: 800, timeBlindSamples: 3 },
    must: ['time'],
    nice: [],
  },
  {
    name: 'stacked',
    desc: '堆叠注入（; 第二条语句 sleep）',
    url: `${BASE}/stacked?i=1`,
    config: { techniques: ['stacked'], timeBlindSleepSec: 1, timeThresholdMs: 800, timeBlindSamples: 3 },
    must: ['stacked'],
    nice: [],
  },
  {
    name: 'inline',
    desc: '内联查询（对标 sqlmap Q：标量子查询随响应回显）',
    url: `${BASE}/num?id=1`,
    config: { techniques: ['inline'] },
    must: ['inline'],
    nice: [],
  },
  {
    name: 'union_extract',
    desc: 'UNION 提取链（版本值经 __S__..__E__ 回显可拖库）',
    url: `${BASE}/num?id=1`,
    config: { techniques: ['union'], enableExtract: true },
    must: ['union'],
    nice: [],
    checkExtracted: true,
  },
  {
    name: 'search_like',
    desc: '搜索型注入（LIKE %{v}% 上下文，需 % 与 \' 双闭合；裸 %…% 字面量恒真、尾部 % 比较走前缀匹配）',
    url: `${BASE}/search?q=alice`,
    config: { techniques: ['boolean'] },
    must: ['boolean'],
    nice: [],
  },
  {
    name: 'update_set',
    desc: 'UPDATE SET 注入（name=\'…\' 赋值上下文，引号闭合后逗号拼接赋值；纯字面量恒真）',
    url: `${BASE}/update?id=1&name=alice`,
    config: { techniques: ['boolean'] },
    must: ['boolean'],
    nice: [],
  },
];

// 真实 SQLite 检测场景组（direct 模式，经 SqlJsDriver 在真实 SQLite 上执行完整检测链路）
const REAL_SCENARIOS = [
  {
    name: 'real_numeric',
    desc: '真实 SQLite 数值型注入（UNION/布尔/报错完整链路）',
    target: buildTarget('1', 'numeric'),
    config: { techniques: ['union', 'boolean', 'error'], ratePerSec: 0, concurrency: 2 },
    must: ['boolean', 'union'],
    nice: ['error'],
  },
  {
    name: 'real_str',
    desc: "真实 SQLite 字符串上下文（name='…'，需 ' 闭合）",
    target: buildTarget('Alice', 'str'),
    config: { techniques: ['boolean', 'union'], ratePerSec: 0, concurrency: 2 },
    must: ['boolean'],
    nice: ['union'],
  },
  {
    name: 'real_dump',
    desc: '真实 SQLite UNION 提取链（dumpData 返回真实行）',
    target: buildTarget('1', 'union'),
    config: { techniques: ['union'], enableExtract: true, ratePerSec: 0, concurrency: 2 },
    must: ['union'],
    nice: [],
    checkExtracted: true,
  },
];

const baseConfig = {
  concurrency: 4,
  ratePerSec: 0, // 本地靶场不限速（0 = 不启用限速桶）
  retry: 0,
  timeoutMs: 12_000,
  enableExtract: false, // 召回只验检测，不做数据提取
  // 注：不要部分覆盖 blindRobust（会整体替换对象、丢失 baselineSamples/minStableRatio 等
  // 子字段导致鲁棒分支失灵）——defaults 已默认启用，保持缺省即可。
};

function fmtMs(ms) {
  return ms >= 1000 ? `${(ms / 1000).toFixed(1)}s` : `${ms}ms`;
}

// 驱动一次扫描：轮询 scans Map 直到 completed/error/超时
async function runScan(sm, scenario) {
  const startedAt = Date.now();
  const mergedConfig = { ...baseConfig, ...scenario.config };
  const scanId = await sm.start(
    scenario.target
      ? { ...scenario.target, config: mergedConfig }
      : { url: scenario.url, config: mergedConfig }
  );
  for (;;) {
    const s = sm.scans.get(scanId);
    if (s && (s.status === 'completed' || s.status === 'error')) break;
    if (Date.now() - startedAt > SCENARIO_TIMEOUT_MS) {
      sm.stop(scanId).catch(() => {});
      return { status: 'timeout', vulns: [], elapsedMs: Date.now() - startedAt };
    }
    await new Promise((r) => setTimeout(r, 20));
  }
  const report = sm.getReport(scanId) || { vulns: [] };
  return {
    status: sm.scans.get(scanId)?.status || 'unknown',
    vulns: report.vulns || [],
    data: report.data ?? null,
    elapsedMs: Date.now() - startedAt,
  };
}

async function main() {
  const { server, stats, resetStats } = createRecallLab();
  await new Promise((resolveListen) => server.listen(PORT, '127.0.0.1', resolveListen));
  console.log(`[recall-e2e] lab 已启动：${BASE}`);

  const rows = [];
  let failed = false;
  let realSkipped = false;
  let useReal = false;
  try {
    for (const sc of SCENARIOS) {
      resetStats();
      const t0 = Date.now();
      const sm = new ScanManager();
      const out = await runScan(sm, sc);
      const found = new Set(out.vulns.map((v) => v.technique));
      const mustMiss = sc.must.filter((t) => !found.has(t));
      const niceHit = sc.nice.filter((t) => found.has(t));
      // union_extract 场景额外校验：提取数据（databases/tables）非空 —— 提取链回归红线
      let extractOk = true;
      if (sc.checkExtracted) {
        const d = out.data;
        const hasAny =
          d && Array.isArray(d.databases) && d.databases.length > 0;
        const hasTables =
          d && typeof d.tables === 'object' && d.tables != null && Object.keys(d.tables).length > 0;
        extractOk = hasAny && hasTables;
        if (!extractOk) failed = true;
      }
      const ok = out.status === 'completed' && mustMiss.length === 0 && extractOk;
      if (!ok) failed = true;
      rows.push({
        ...sc,
        status: out.status,
        found: [...found],
        mustMiss,
        niceHit,
        requests: stats.total,
        sleepMs: stats.sleepMs,
        elapsedMs: Date.now() - t0,
        extractOk: sc.checkExtracted ? extractOk : undefined,
        ok,
      });
      const mark = ok ? 'PASS' : 'FAIL';
      const extTag = sc.checkExtracted ? (extractOk ? ' 提取✓' : ' 提取✗') : '';
      console.log(
        `[${mark}] ${sc.name}（${sc.desc}）检出=[${[...found].join(',') || '-'}] ` +
          `miss=[${mustMiss.join(',') || '-'}]${extTag} 请求=${stats.total} 耗时=${fmtMs(Date.now() - t0)}`
      );
      // 场景间稍歇，让 _retire TTL 异步回收不互相干扰
      await new Promise((r) => setTimeout(r, 150));
    }

    // —— 真实 SQLite 场景组（direct 模式，真实 DB 执行检测链路）——
    // sql.js 可用时跑 REAL_SCENARIOS；不可用时打印跳过提示（不 fail）。
    const useRealNow = await sqljsAvailable();
    if (useRealNow) {
      useReal = true;
      console.log('[recall-e2e] sql.js 可用，运行真实 SQLite 场景');
      for (const sc of REAL_SCENARIOS) {
        resetStats();
        const t0 = Date.now();
        const sm = new ScanManager();
        const out = await runScan(sm, sc);
        const found = new Set(out.vulns.map((v) => v.technique));
        const mustMiss = sc.must.filter((t) => !found.has(t));
        const niceHit = sc.nice.filter((t) => found.has(t));
        let extractOk = true;
        if (sc.checkExtracted) {
          const d = out.data;
          const hasAny =
            d && Array.isArray(d.databases) && d.databases.length > 0;
          const hasTables =
            d && typeof d.tables === 'object' && d.tables != null && Object.keys(d.tables).length > 0;
          extractOk = hasAny && hasTables;
          if (!extractOk) failed = true;
        }
        const ok = out.status === 'completed' && mustMiss.length === 0 && extractOk;
        if (!ok) failed = true;
        rows.push({
          ...sc,
          status: out.status,
          found: [...found],
          mustMiss,
          niceHit,
          requests: 0, // direct 模式不经 HTTP，无请求计数
          sleepMs: 0,
          elapsedMs: Date.now() - t0,
          extractOk: sc.checkExtracted ? extractOk : undefined,
          ok,
        });
        const mark = ok ? 'PASS' : 'FAIL';
        const extTag = sc.checkExtracted ? (extractOk ? ' 提取✓' : ' 提取✗') : '';
        console.log(
          `[${mark}] ${sc.name}（${sc.desc}）检出=[${[...found].join(',') || '-'}] ` +
            `miss=[${mustMiss.join(',') || '-'}]${extTag} 耗时=${fmtMs(Date.now() - t0)}`
        );
        await new Promise((r) => setTimeout(r, 150));
      }
    } else {
      console.log('[recall-e2e] sql.js 不可用，跳过真实库场景（不 fail）');
      realSkipped = true;
    }

    // —— 真实 PostgreSQL 场景组（PGlite WASM，验证 PG 方言 payload）——
    const usePgNow = await pgAvailable();
    if (usePgNow) {
      console.log('[recall-e2e] PGlite 可用，运行真实 PostgreSQL 场景');
      const PG_SCENARIOS = [
        {
          name: 'real_pg_numeric',
          desc: '真实 PG 数值型注入（UNION/布尔/报错，验证 PG 方言）',
          target: buildPgTarget('1', 'numeric'),
          config: { techniques: ['union', 'boolean', 'error'], ratePerSec: 0, concurrency: 2, dbms: 'PostgreSQL' },
          must: ['boolean'],
          nice: ['union', 'error'],
        },
        {
          name: 'real_pg_str',
          desc: "真实 PG 字符串上下文（name='…'，需 ' 闭合）",
          target: buildPgTarget('alice', 'str'),
          config: { techniques: ['boolean', 'union'], ratePerSec: 0, concurrency: 2, dbms: 'PostgreSQL' },
          must: ['boolean'],
          nice: ['union'],
        },
      ];
      for (const sc of PG_SCENARIOS) {
        resetStats();
        const t0 = Date.now();
        const sm = new ScanManager();
        const out = await runScan(sm, sc);
        const found = new Set(out.vulns.map((v) => v.technique));
        const mustMiss = sc.must.filter((t) => !found.has(t));
        const niceHit = sc.nice.filter((t) => found.has(t));
        const ok = out.status === 'completed' && mustMiss.length === 0;
        if (!ok) failed = true;
        rows.push({ ...sc, status: out.status, found: [...found], mustMiss, niceHit, requests: 0, sleepMs: 0, elapsedMs: Date.now() - t0, ok });
        const mark = ok ? 'PASS' : 'FAIL';
        console.log(
          `[${mark}] ${sc.name}（${sc.desc}）检出=[${[...found].join(',') || '-'}] ` +
            `miss=[${mustMiss.join(',') || '-'}] 耗时=${fmtMs(Date.now() - t0)}`
        );
        await new Promise((r) => setTimeout(r, 150));
      }
    } else {
      console.log('[recall-e2e] PGlite 不可用，跳过真实 PG 场景（不 fail）');
    }

    // —— 真实 MySQL 场景组（mysql2 驱动，连接本地 mysqld/MariaDB）——
    const useMysqlNow = await mysqlAvailable();
    if (useMysqlNow) {
      console.log('[recall-e2e] mysql2 可用，运行真实 MySQL 场景');
      const MYSQL_SCENARIOS = [
        {
          name: 'real_mysql_numeric',
          desc: '真实 MySQL 数值型注入（UNION/布尔/报错，验证 MySQL 方言）',
          target: buildMysqlTarget('1', 'numeric'),
          config: { techniques: ['union', 'boolean', 'error'], ratePerSec: 0, concurrency: 2, dbms: 'MySQL' },
          must: ['boolean'],
          nice: ['union', 'error'],
        },
        {
          name: 'real_mysql_str',
          desc: "真实 MySQL 字符串上下文（name='…'，需 ' 闭合）",
          target: buildMysqlTarget('alice', 'str'),
          config: { techniques: ['boolean', 'union'], ratePerSec: 0, concurrency: 2, dbms: 'MySQL' },
          must: ['boolean'],
          nice: ['union'],
        },
      ];
      for (const sc of MYSQL_SCENARIOS) {
        resetStats();
        const t0 = Date.now();
        const sm = new ScanManager();
        const out = await runScan(sm, sc);
        const found = new Set(out.vulns.map((v) => v.technique));
        const mustMiss = sc.must.filter((t) => !found.has(t));
        const niceHit = sc.nice.filter((t) => found.has(t));
        const ok = out.status === 'completed' && mustMiss.length === 0;
        if (!ok) failed = true;
        rows.push({ ...sc, status: out.status, found: [...found], mustMiss, niceHit, requests: 0, sleepMs: 0, elapsedMs: Date.now() - t0, ok });
        const mark = ok ? 'PASS' : 'FAIL';
        console.log(
          `[${mark}] ${sc.name}（${sc.desc}）检出=[${[...found].join(',') || '-'}] ` +
            `miss=[${mustMiss.join(',') || '-'}] 耗时=${fmtMs(Date.now() - t0)}`
        );
        await new Promise((r) => setTimeout(r, 150));
      }
    } else {
      console.log('[recall-e2e] mysql2 不可用，跳过真实 MySQL 场景（不 fail）');
    }
  } finally {
    server.close();
  }

  // 产出基线矩阵
  mkdirSync(RESULTS_DIR, { recursive: true });
  const now = new Date().toISOString();
  const md = [
    '# 检测召回基线（recall-lab）',
    '',
    `> 生成时间：${now}　｜　靶场：${BASE}（微型注入 SQL 求值器，node:http 零依赖）` +
      `${useReal ? '　｜　真实库组：sql.js（真实 SQLite，direct 模式）' : ''}`,
    `> 运行：\`npm run recall-e2e\`　｜　must 未命中即 exit 1（回归红线）；nice 仅记录` +
      `${realSkipped ? '　｜　⚠ sql.js 不可用，真实库场景已跳过' : ''}`,
    '',
    '| 场景 | 上下文 | must | 检出 | nice 命中 | 请求数 | sleep(s) | 耗时 | 结果 |',
    '|---|---|---|---|---|---|---|---|---|',
    ...rows.map(
      (r) =>
        `| ${r.name} | ${r.desc} | ${r.must.join('+')} | ${r.found.join(', ') || '-'} | ` +
        `${r.niceHit.join(', ') || '-'} | ${r.requests} | ${(r.sleepMs / 1000).toFixed(1)} | ${fmtMs(r.elapsedMs)} | ${r.ok ? '✅' : '❌'} |`
    ),
    '',
    `**总计**：${rows.length} 场景，${rows.filter((r) => r.ok).length} 通过；` +
      `请求 ${rows.reduce((a, r) => a + r.requests, 0)}，墙钟 ${fmtMs(rows.reduce((a, r) => a + r.elapsedMs, 0))}`,
    '',
  ].join('\n');
  writeFileSync(resolve(RESULTS_DIR, 'recall.md'), md, 'utf8');
  console.log(`[recall-e2e] 基线已写入 e2e/recall-lab/results/recall.md`);
  if (failed) {
    console.error('[recall-e2e] 存在 must 未命中场景，回归失败');
    process.exitCode = 1;
  }
}

main().catch((e) => {
  console.error('[recall-e2e] 运行异常：', e);
  process.exitCode = 1;
});
