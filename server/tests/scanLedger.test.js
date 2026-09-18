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
import { mkdtempSync, rmSync, readFileSync, existsSync, readdirSync, appendFileSync } from 'node:fs';
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
