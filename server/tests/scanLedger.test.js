// [2026-09-18] 扫描台账（scanLedger）直接单测。
//
// 为什么补这一组（TODO P2-6「弱引用模块补直接单测」的真实落点）：
// 覆盖率报告显示 scanLedger 的函数覆盖 0%、行覆盖 26.39% —— 因为它只被 bin/cli.js 调用，
// 而 CLI 走 e2e 不入单测。但它是**真实交付路径**：`cli.js ledger list/show` 直接消费它，
// 且 163 次真实台账已积累在 server/data/ledger。
//
// 补测过程中实测到三个真实缺陷（均已修，本文件锁定修复）：
//   ① PoC 落盘恒为空：recordScan 依赖 v.poc，而 poc 是 ReportGenerator 惰性且**不可变**
//      挂载的（_attachPoc 返回新对象、不回写入参）。CLI 传原始 report → `if (!v.poc) continue`
//      全命中 → poc/ 恒空。实测 163 个真实台账目录、0 个 poc 文件。
//   ② getScan 的 files 分隔符随平台（Windows 得 `poc\a.txt`），与 recordScan 写入
//      meta.files 的 `poc/a.txt` 口径不一致 → 消费方按 `startsWith('poc/')` 过滤恒为空。
//   ③ scanId 可路径穿越：`../x` 能把目录建到 ledger 根目录之外（recordScan/getScan 均可达，
//      getScan 的 scanId 还直接来自 CLI 参数）。
//
// 全部用例基于真实文件系统（临时目录），不 mock 落盘 —— 这三条缺陷恰恰是"文档说有、
// 实际没有"型，mock 掉 fs 就永远发现不了。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, rmSync, readFileSync, existsSync, readdirSync, appendFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ReportGenerator } from '../src/services/ReportGenerator.js';

// scanLedger 在模块顶层读 process.env.SQLI_LEDGER_DIR 之外、每次调用都重新求值 ledgerDir()，
// 因此可以在测试内改写环境变量切换台账根目录（不必重置模块）。
const scanLedger = await import('../src/services/scanLedger.js');

/** 在独立的临时台账目录内跑一段用例，结束后清理 */
function withLedger(fn) {
  const dir = mkdtempSync(join(tmpdir(), 'ledger-test-'));
  const prev = process.env.SQLI_LEDGER_DIR;
  process.env.SQLI_LEDGER_DIR = dir;
  try {
    return fn(dir);
  } finally {
    if (prev === undefined) delete process.env.SQLI_LEDGER_DIR;
    else process.env.SQLI_LEDGER_DIR = prev;
    rmSync(dir, { recursive: true, force: true });
  }
}

const rg = new ReportGenerator();

/** 贴近真实 report.json 形态的最小报告（vuln 无 poc 字段，与引擎产出同形） */
function mkReport(overrides = {}) {
  return {
    scanId: 'scan-t1',
    target: { url: 'http://127.0.0.1:8151/items?cat=1', method: 'GET', config: {} },
    startedAt: '2026-09-18T01:00:00.000Z',
    finishedAt: '2026-09-18T01:00:05.000Z',
    points: [{ id: 'p1', url: 'http://127.0.0.1:8151/items?cat=1', method: 'GET', param: 'cat' }],
    vulns: [
      {
        id: 'v1',
        pointId: 'p1',
        technique: 'union',
        dbms: 'MySQL',
        riskLevel: 'high',
        payloads: ["1 UNION SELECT NULL,'SQLISCANNER1',NULL,NULL,NULL-- -", "1 ORDER BY 5-- -"],
        evidence: 'UNION 注入成功',
        url: 'http://127.0.0.1:8151/items?cat=1',
        method: 'GET',
        param: 'cat',
        affectedParam: 'cat',
      },
    ],
    summary: { verdict: 'no_vulnerability_detected' },
    dbms: 'MySQL',
    ...overrides,
  };
}

test('recordScan: 落盘 meta/report 并追加全局索引', () => {
  withLedger((dir) => {
    const rec = scanLedger.recordScan(mkReport(), { html: '<html/>', markdown: '# md', json: '{"k":1}' });
    assert.equal(rec.scanId, 'scan-t1');
    assert.ok(existsSync(join(rec.dir, 'meta.json')));
    assert.ok(existsSync(join(rec.dir, 'report.json')));
    assert.ok(existsSync(join(rec.dir, 'report.html')));
    assert.ok(existsSync(join(rec.dir, 'report.md')));
    // docs.json 优先于自动序列化
    assert.equal(readFileSync(join(rec.dir, 'report.json'), 'utf8'), '{"k":1}');
    // 全局索引一行
    const idx = readFileSync(join(dir, 'index.jsonl'), 'utf8').split('\n').filter(Boolean);
    assert.equal(idx.length, 1);
    assert.equal(JSON.parse(idx[0]).scanId, 'scan-t1');
  });
});

test('recordScan: verdict 口径与 vulns 一致（vulns>0 不得报 no_vulnerability_detected）', () => {
  // [goal-FIX 2026-09-16] 回归钉：真实台账里曾出现 vulns=3 却 verdict=no_vulnerability_detected
  // 的交付级自相矛盾。此断言防它再次出现。
  withLedger((dir) => {
    scanLedger.recordScan(mkReport());
    const meta = JSON.parse(readFileSync(join(dir, 'scan-t1', 'meta.json'), 'utf8'));
    assert.equal(meta.vulns, 1);
    assert.equal(meta.verdict, 'vulnerability_detected');
  });
  withLedger((dir) => {
    // 无命中时才透传 summary.verdict
    scanLedger.recordScan(mkReport({ scanId: 'scan-t2', vulns: [], summary: { verdict: 'inconclusive' } }));
    const meta = JSON.parse(readFileSync(join(dir, 'scan-t2', 'meta.json'), 'utf8'));
    assert.equal(meta.verdict, 'inconclusive');
  });
});

test('recordScan: payloadHits 统计所有 payload（含重复）', () => {
  withLedger((dir) => {
    scanLedger.recordScan(mkReport());
    const meta = JSON.parse(readFileSync(join(dir, 'scan-t1', 'meta.json'), 'utf8'));
    assert.equal(meta.payloadHits, 2, 'vulns[0].payloads 有 2 条');
  });
});

test('recordScan: 传 ReportGenerator.attachPoc() 形态才落 PoC（缺陷① 回归钉）', () => {
  withLedger((dir) => {
    // —— 反例：原始 report（poc 未挂载）→ poc/ 为空目录 ——
    const raw = mkReport({ scanId: 'scan-raw' });
    scanLedger.recordScan(raw, { html: 'x', markdown: 'y' });
    const rawPocDir = join(dir, 'scan-raw', 'poc');
    assert.ok(existsSync(rawPocDir), 'poc 目录总会被创建');
    assert.equal(readdirSync(rawPocDir).length, 0, '原始 report 无 poc 字段 → poc/ 必为空');
    assert.equal(raw.vulns[0].poc, undefined, 'attachPoc 不可变：不得回写入参');
  });
  withLedger((dir) => {
    // —— 正例：attachPoc 形态 → PoC 落盘，且内容是可直接复放的原生报文 ——
    const report = mkReport({ scanId: 'scan-fixed' });
    scanLedger.recordScan(rg.attachPoc(report), { html: rg.toHTML(report), markdown: rg.toMarkdown(report) });
    const pocDir = join(dir, 'scan-fixed', 'poc');
    const files = readdirSync(pocDir);
    assert.ok(files.length >= 1, 'attachPoc 形态必须落出 PoC 文件');
    assert.match(files[0], /^poc-\d+-\d+-p1\.txt$/);
    const body = readFileSync(join(pocDir, files[0]), 'utf8');
    assert.match(body, /^GET \/items\?cat=1 HTTP\/1\.1/, 'PoC 应为原生 HTTP 报文（-r 可导入）');
    // report.json 同步带 poc（recordScan 收到的是导出形态）
    const saved = JSON.parse(readFileSync(join(dir, 'scan-fixed', 'report.json'), 'utf8'));
    assert.ok(saved.vulns[0].poc, '落盘的 report.json 应含 poc 证据链');
  });
});

test('recordScan: poC 文件名按 pointId 编号，重复 payload 去重', () => {
  withLedger((dir) => {
    const report = mkReport({
      scanId: 'scan-dup',
      vulns: [
        { pointId: 'pA', technique: 'union', payloads: ['1', '1', '2'], poc: { raw: 'R' } },
      ],
    });
    scanLedger.recordScan(report);
    const files = readdirSync(join(dir, 'scan-dup', 'poc')).sort();
    assert.equal(files.length, 2, 'payload 1 重复出现两次 → 只落 1 份');
    assert.deepEqual(files, ['poc-1-1-pA.txt', 'poc-1-2-pA.txt']);
  });
});

test('getScan: files 用 / 分隔且与 recordScan 的 meta.files 口径一致（缺陷② 回归钉）', () => {
  withLedger((dir) => {
    const report = mkReport({ scanId: 'scan-sep' });
    scanLedger.recordScan(rg.attachPoc(report), { html: 'h', markdown: 'm' });
    const got = scanLedger.getScan('scan-sep');
    assert.ok(got);
    // 关键：不得出现平台分隔符（Windows 下 join 会产生 `poc\a.txt`）
    for (const f of got.files) assert.ok(!f.includes('\\'), `files 不得含反斜杠：${f}`);
    assert.ok(got.files.some((f) => f.startsWith('poc/')), '消费方按 poc/ 前缀过滤必须命中');
    // 与写入 meta.files 的集合一致（getScan 额外含 meta.json 自身）
    const meta = JSON.parse(readFileSync(join(dir, 'scan-sep', 'meta.json'), 'utf8'));
    for (const f of meta.files) assert.ok(got.files.includes(f), `meta.files 中的 ${f} 应出现在 getScan.files`);
  });
});

test('getScan/listScans: 非法或不存在时安全返回', () => {
  withLedger(() => {
    assert.equal(scanLedger.getScan('no-such-scan'), null);
    assert.deepEqual(scanLedger.listScans(5), []);
  });
});

test('scanId 路径穿越必须被拒（缺陷③ 回归钉）', () => {
  withLedger((dir) => {
    for (const evil of ['../escape', '..\\escape', '/abs/path', 'C:/win/path', 'a/b', '..']) {
      assert.throws(
        () => scanLedger.recordScan({ scanId: evil, vulns: [], points: [], target: {} }),
        /非法 scanId/,
        `recordScan 应拒绝 scanId=${JSON.stringify(evil)}`,
      );
    }
    // getScan 的 scanId 直接来自 CLI 参数，同样须拒绝
    for (const evil of ['../escape', 'a/b', '..']) {
      assert.throws(() => scanLedger.getScan(evil), /非法 scanId/, `getScan 应拒绝 ${evil}`);
    }
    // 空字符串是假值 → 走 scanId 回退生成（等同未提供），不算穿越路径
    const rec = scanLedger.recordScan({ scanId: '', vulns: [], points: [], target: {}, summary: {} });
    assert.match(rec.scanId, /^scan-\d+$/);
  });

  // 越界写入必须真的没发生：以一个自建的父目录为台账根，扫描其下所有条目，
  // 断言唯一子目录就是合法的回退 scanId —— 不依赖系统 tmp 里是否有无关残留。
  const parent = mkdtempSync(join(tmpdir(), 'ledger-escape-'));
  const prev = process.env.SQLI_LEDGER_DIR;
  process.env.SQLI_LEDGER_DIR = join(parent, 'ledger');
  try {
    scanLedger.recordScan({ scanId: '../escaped', vulns: [], points: [], target: {} }).scanId; // 应抛
    assert.fail('越界 scanId 未抛错');
  } catch (e) {
    assert.match(e.message, /非法 scanId/);
  }
  try {
    // 台账根自身都没被建立（recordScan 在 safeScanId 处就抛了，未触达 mkdir）
    const siblings = readdirSync(parent);
    assert.deepEqual(siblings, [], `父目录不得出现任何越界产物，实际：${JSON.stringify(siblings)}`);
  } finally {
    if (prev === undefined) delete process.env.SQLI_LEDGER_DIR;
    else process.env.SQLI_LEDGER_DIR = prev;
    rmSync(parent, { recursive: true, force: true });
  }
});

test('listScans: 取最新 limit 条并按 新→旧 返回', () => {
  withLedger(() => {
    for (const id of ['s1', 's2', 's3']) {
      scanLedger.recordScan({ scanId: id, vulns: [], points: [], target: {}, summary: {} });
    }
    // 索引为追加写（旧→新），listScans 取尾部再反转
    assert.deepEqual(scanLedger.listScans(10).map((r) => r.scanId), ['s3', 's2', 's1']);
    assert.deepEqual(scanLedger.listScans(2).map((r) => r.scanId), ['s3', 's2'], 'limit 语义 = 最新 N 条');
    assert.equal(scanLedger.listScans(1)[0].scanId, 's3');
  });
});

test('listScans: 容忍索引中的损坏行（跳过而非整体失败）', () => {
  withLedger((dir) => {
    scanLedger.recordScan({ scanId: 'ok-1', vulns: [], points: [], target: {}, summary: {} });
    const idx = join(dir, 'index.jsonl');
    appendFileSync(idx, '{ 这不是合法 JSON\n', 'utf-8');
    scanLedger.recordScan({ scanId: 'ok-2', vulns: [], points: [], target: {}, summary: {} });
    assert.deepEqual(scanLedger.listScans(10).map((r) => r.scanId), ['ok-2', 'ok-1']);
  });
});

test('recordScan: report 缺失/非法时抛错', () => {
  withLedger(() => {
    assert.throws(() => scanLedger.recordScan(null), /report required/);
    assert.throws(() => scanLedger.recordScan(undefined), /report required/);
    assert.throws(() => scanLedger.recordScan('not-an-object'), /report required/);
  });
});

test('recordScan: 缺 scanId 时回退生成（不抛错）', () => {
  withLedger(() => {
    const rec = scanLedger.recordScan({ vulns: [], points: [], target: {}, summary: {} });
    assert.match(rec.scanId, /^scan-\d+$/);
  });
});

// ============================================================================
// 台账保留策略 pruneLedger（2026-09-29，TODO「接口靶场遗留项」第 5 条）
//
// 判据纪律：不采信 pruneLedger 自报的 removed 数字——那是它自己算的。
// 每条都额外断言**外部事实**：目录存不存在（existsSync）、索引里还有没有那行
// （readFileSync）、readReport 是不是真的读不到了。自报与实际不一致就要红。
// ============================================================================
const NOW = Date.parse('2026-09-29T00:00:00.000Z');

/** 在临时台账里连续登记若干条（finishedAt 按距今天数回溯） */
function recordSeries(entries) {
  for (const e of entries) {
    scanLedger.recordScan({
      scanId: e.id,
      finishedAt: new Date(NOW - e.daysAgo * 86400000).toISOString(),
      vulns: [], points: [], target: {}, summary: {},
    });
  }
}

/** 临时改写保留策略环境变量并执行 fn（退出后原样还原，防污染同进程其它用例） */
function withPolicy(policy, fn) {
  // ⚠️ policy 用的是短名（max/maxDays），环境变量是另一套名 —— 早写成直接 setenv(policy 的 key)
  //    的话进程里根本不存在 SCAN_LEDGER_MAX，pruneLedger 一路报 no-limit、九条用例全红。
  const map = { max: 'SCAN_LEDGER_MAX', maxDays: 'SCAN_LEDGER_MAX_DAYS' };
  const keys = Object.values(map);
  const saved = {};
  for (const k of keys) saved[k] = process.env[k];
  try {
    for (const [k, v] of Object.entries(policy)) {
      const envKey = map[k] || k;
      if (v === null || v === undefined) delete process.env[envKey];
      else process.env[envKey] = String(v);
    }
    return fn();
  } finally {
    for (const k of keys) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
  }
}

test('recordScan: meta.highestRisk 取 vulns 里的最高风险（History 页接服务端后靠它出色标）', () => {
  const mk = (vulns) => withLedger((dir) => {
    scanLedger.recordScan({ ...mkReport({ scanId: 'risk-1' }), vulns });
    return JSON.parse(readFileSync(join(dir, 'risk-1', 'meta.json'), 'utf8'));
  });
  assert.equal(mk([
    { riskLevel: 'Low' }, { riskLevel: 'Critical' }, { riskLevel: 'Medium' },
  ]).highestRisk, 'Critical', '必须按 Low<Medium<High<Critical 取最大，不是取第一条');
  assert.equal(mk([{ riskLevel: 'High' }, { riskLevel: 'Low' }]).highestRisk, 'High');
  assert.equal(mk([]).highestRisk, null, '无漏洞 ⇒ null，不得兜底成 Low');
  // 非规范值：跳过而不是把 i18n key 脏染到 UI（前端 t('risk.'+lower) 会渲染出 key 原文）
  assert.equal(mk([{ riskLevel: 'unknown-level' }]).highestRisk, null);
  assert.equal(mk([{ riskLevel: 'High' }, { riskLevel: 'weird' }]).highestRisk, 'High', '脏值不得拉低已算出的等级');
});

test('pruneLedger: 未配置策略 ⇒ 一个都不删（默认零行为变化）', () => {
  withLedger(() => {
    recordSeries([{ id: 'a', daysAgo: 30 }, { id: 'b', daysAgo: 20 }, { id: 'c', daysAgo: 1 }]);
    const r = withPolicy({ max: null, maxDays: null }, () => scanLedger.pruneLedger({ now: NOW }));
    assert.equal(r.skipped, true);
    assert.equal(r.reason, 'no-limit');
    assert.equal(r.removed, 0);
    // 除了"没删东西"，还要钉住"策略本身就是零"：若 positiveInt 偷偷给了默认值，
    // 只看删没删（条目少时都不删）是绿的，部署到生产才突然开始清历史。
    assert.deepEqual(scanLedger.retentionPolicy(), { max: 0, maxDays: 0 });
    // 外部事实：三条都还在
    assert.deepEqual(scanLedger.listScans(10).map((x) => x.scanId), ['c', 'b', 'a']);
  });
});

test('pruneLedger: max 按时间保留最新 N 条，目录与索引成对消失', () => {
  withLedger((dir) => {
    recordSeries([{ id: 'old', daysAgo: 9 }, { id: 'mid', daysAgo: 5 }, { id: 'new', daysAgo: 0 }]);
    const r = withPolicy({ max: 2, maxDays: null }, () => scanLedger.pruneLedger({ now: NOW }));
    assert.equal(r.skipped, false);
    assert.equal(r.removed, 1);
    assert.deepEqual(r.removedIds, ['old']);
    assert.equal(r.failed.length, 0, '不应有删除失败项');
    // 目录真的没了（不是只在 self-report 里说删了）
    assert.equal(existsSync(join(dir, 'old')), false, '被淘汰目录必须真的从磁盘消失');
    assert.equal(existsSync(join(dir, 'mid')), true, '保留条目不得被误删');
    // 索引真的没那行了（只删目录不删索引 ⇒ 列表还在、点开 404，是最坏形态）
    assert.deepEqual(scanLedger.listScans(10).map((x) => x.scanId), ['new', 'mid']);
    const idxText = readFileSync(join(dir, 'index.jsonl'), 'utf8');
    assert.equal(idxText.includes('"scanId":"old"'), false, '索引行必须一并移除');
  });
});

test('pruneLedger: 淘汰后 readReport 返回 null（⇒ /scan/:id/report 走 404 而非半份数据）', () => {
  withLedger(() => {
    recordSeries([{ id: 'old', daysAgo: 9 }, { id: 'new', daysAgo: 0 }]);
    withPolicy({ max: 1, maxDays: null }, () => scanLedger.pruneLedger({ now: NOW }));
    // 这条直接对应 TODO 第 5 条的验收口径
    assert.equal(scanLedger.readReport('old'), null, '淘汰后必须读不到报告（⇒ 404）');
    assert.equal(scanLedger.getScan('old'), null, 'meta.json 也不该还在');
    assert.ok(scanLedger.readReport('new'), '保留条目仍要能读');
  });
});

test('pruneLedger: maxDays 按 finishedAt 淘汰过期条目', () => {
  withLedger((dir) => {
    recordSeries([{ id: 'd40', daysAgo: 40 }, { id: 'd10', daysAgo: 10 }, { id: 'd2', daysAgo: 2 }]);
    const r = withPolicy({ max: null, maxDays: 30 }, () => scanLedger.pruneLedger({ now: NOW }));
    assert.deepEqual(r.removedIds, ['d40']);
    assert.equal(existsSync(join(dir, 'd40')), false);
    assert.equal(existsSync(join(dir, 'd10')), true);
  });
});

test('pruneLedger: max 与 maxDays 叠加（先过天数，再按条目数截断）', () => {
  withLedger((dir) => {
    recordSeries([{ id: 'd40', daysAgo: 40 }, { id: 'd10', daysAgo: 10 }, { id: 'd2', daysAgo: 2 }]);
    const r = withPolicy({ max: 1, maxDays: 30 }, () => scanLedger.pruneLedger({ now: NOW }));
    assert.deepEqual(r.removedIds.sort(), ['d10', 'd40'], '天数淘汰后剩下的再按新旧只留 1 条');
    assert.equal(existsSync(join(dir, 'd40')), false);
    assert.equal(existsSync(join(dir, 'd10')), false);
    assert.equal(existsSync(join(dir, 'd2')), true, '最新那条必须活下来');
  });
});

test('pruneLedger: 无时间戳的条目排最前被淘汰（不得兜底成"永远最新"）', () => {
  withLedger((dir) => {
    recordSeries([{ id: 'new', daysAgo: 0 }, { id: 'older', daysAgo: 3 }]);
    // 手工塞一条完全没有时间字段的索引行 —— 真实来源是 index.jsonl 被外部工具回写
    appendFileSync(join(dir, 'index.jsonl'), `${JSON.stringify({ scanId: 'notime', target: '-' })}\n`, 'utf-8');
    const r = withPolicy({ max: 2, maxDays: null }, () => scanLedger.pruneLedger({ now: NOW }));
    assert.ok(r.removedIds.includes('notime'), '缺时间戳 ⇒ 视为最老 ⇒ 优先出局');
    assert.equal(existsSync(join(dir, 'older')), true, '有时间字段的旧条目应活下来');
  });
});

test('pruneLedger: 索引里的非法 JSON 行被原样保留（不得因清理丢数据）', () => {
  withLedger((dir) => {
    recordSeries([{ id: 'a', daysAgo: 9 }, { id: 'b', daysAgo: 1 }]);
    const bad = '{ 这不是合法 JSON';
    appendFileSync(join(dir, 'index.jsonl'), `${bad}\n`, 'utf-8');
    withPolicy({ max: 1, maxDays: null }, () => scanLedger.pruneLedger({ now: NOW }));
    const idxText = readFileSync(join(dir, 'index.jsonl'), 'utf8');
    assert.ok(idxText.includes(bad), '坏行不参与判定，但必须留回文件里');
    assert.equal(idxText.split('\n').filter(Boolean).length, 2, '1 条保留 + 1 条坏行');
  });
});

test('pruneLedger: 同一 scanId 重复登记时收敛成一行（附加 Fixes 列表重复项）', () => {
  withLedger(() => {
    recordSeries([{ id: 'dup', daysAgo: 5 }]);
    recordSeries([{ id: 'dup', daysAgo: 0 }]); // 同一 scanId 再记一次
    assert.equal(scanLedger.listScans(10).filter((r) => r.scanId === 'dup').length, 2, '清理前确实是两条');
    withPolicy({ max: 5, maxDays: null }, () => scanLedger.pruneLedger({ now: NOW }));
    const rows = scanLedger.listScans(10);
    assert.equal(rows.filter((r) => r.scanId === 'dup').length, 1, 'prune 后只应剩最新的一行');
    assert.equal(rows[0].finishedAt, new Date(NOW).toISOString());
  });
});

test('pruneLedger: 非法 scanId（路径穿越）不被删除、只记进 failed', () => {
  withLedger((dir) => {
    recordSeries([{ id: 'ok', daysAgo: 1 }]);
    const outDir = join(dir, '..');
    appendFileSync(join(dir, 'index.jsonl'), `${JSON.stringify({ scanId: '../escape', target: '-' })}\n`, 'utf-8');
    const r = withPolicy({ max: 1, maxDays: null }, () => scanLedger.pruneLedger({ now: NOW }));
    assert.equal(existsSync(join(outDir, 'escape')), false, '『逃逸目标』本来就不存在，也不能被凭空创建/删除');
    assert.ok(r.failed.some((f) => f.id === '../escape'), '非法 id 必须落到 failed 而不是静默跳过');
    assert.equal(existsSync(join(dir, 'ok')), true);
  });
});

test('recordScan: 写入后按策略自我收敛（pruned 字段证明 recordScan 真的调用了 prune）', () => {
  withLedger(() => {
    const r = withPolicy({ max: 2, maxDays: null }, () => {
      recordSeries([{ id: 'a', daysAgo: 9 }, { id: 'b', daysAgo: 5 }]);
      return scanLedger.recordScan({
        scanId: 'c',
        finishedAt: new Date(NOW).toISOString(),
        vulns: [], points: [], target: {}, summary: {},
      });
    });
    assert.ok(r.pruned, 'recordScan 必须回传 prune 结果（否则 prune 写了也没人调用）');
    assert.equal(r.pruned.removed, 1);
    assert.deepEqual(r.pruned.removedIds, ['a']);
    assert.deepEqual(scanLedger.listScans(10).map((x) => x.scanId), ['c', 'b']);
  });
});

test('ledger prune 子命令：--max <N> 空格形态必须真生效（真起 CLI，只认外部事实）', () => {
  // [2026-09-29 收口] args.js 把 --max/--days 登记为「已识别」（cli.unknownFlags.test.js），
  // 若 cli.js 的 argOf 只认 --max=<N> 等号形态，空格形态就成了「无警告、不生效」——
  // 用户以为传上了，实际跑的是环境变量/默认值，恰是 unknownFlags 门禁要防的反面。
  // 判据纪律同本文件其余用例：断言索引行数与目录存亡，不采信 CLI 自报的 removed 数字。
  const CLI_JS = fileURLToPath(new URL('../bin/cli.js', import.meta.url));
  const dir = mkdtempSync(join(tmpdir(), 'ledger-prune-cli-'));
  const write = (id, iso) => {
    mkdirSync(join(dir, id), { recursive: true });
    appendFileSync(join(dir, 'index.jsonl'), JSON.stringify({ scanId: id, recordedAt: iso }) + '\n', 'utf-8');
  };
  write('prune-cli-old', '2026-01-01T00:00:00.000Z');
  write('prune-cli-new', '2026-09-29T00:00:00.000Z');
  const r = spawnSync(process.execPath, [CLI_JS, 'ledger', 'prune', '--max', '1'], {
    encoding: 'utf8',
    env: { ...process.env, SQLI_LEDGER_DIR: dir },
  });
  try {
    assert.equal(r.status, 0, `exit=${r.status} stderr=${r.stderr} stdout=${r.stdout}`);
    const lines = readFileSync(join(dir, 'index.jsonl'), 'utf-8').trim().split('\n');
    assert.equal(lines.length, 1, '索引必须收敛成 1 行');
    assert.match(lines[0], /prune-cli-new/, '保留的必须是最新一条');
    assert.equal(existsSync(join(dir, 'prune-cli-old')), false, '旧目录必须真删掉');
    assert.equal(existsSync(join(dir, 'prune-cli-new')), true, '新目录必须保留');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
