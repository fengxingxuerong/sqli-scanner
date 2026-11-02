// ============================================================================
// server/tests/scanLedger.listTail.guard.test.js —— [D231] 台账列表「尾部截取」必须
// 与「全量解析后取尾部」逐条等价。
//
// 出处（性能实测，2026-11-02）：本机真实台账 `server/data/ledger/index.jsonl`
// 5.8MB / 15605 行，`listScans(50)` 实测 **30~40ms 同步阻塞**——旧实现把整个索引
// split + JSON.parse 完才 `slice(-limit)`，而调用方只要最后几十条
// （REST 列表 50、MCP 500、CLI 默认 50）。台账只增不减，这条成本随使用线性恶化。
//
// ⚠️ 纪律：等价性是本改动唯一的合法性来源。oracle 是 D231 **之前**的实现，
// 任何时候要改"什么算一条登记"，必须同时改 oracle 并在 CHANGELOG 记「语义变更」，
// 不许让 oracle 跟着实现漂移（否则等价性测试退化成自证）。
//
// 特别钉住的边界（旧实现的 `slice(-limit)` 语义）：
//   · `limit = 0`  ⇒ `slice(-0)` === `slice(0)` ⇒ **全量**（不是空数组！）
//   · `limit < 0`  ⇒ 从第 |limit| 条开始取
//   · 行内容为 `0` / `false` / `null` ⇒ 被 `filter(Boolean)` 丢弃，不当成登记
//   · 空行、坏 JSON 行 ⇒ 跳过而不是中断
//   · CRLF 行尾、文件末尾无换行 ⇒ 都要与旧实现一致
// ============================================================================

import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync, mkdirSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { listScans } from '../src/services/scanLedger.js';

// ── oracle：D231 之前的实现（逐字复制，勿"顺手优化"） ──────────────────────
function oldListScans(limit = 50) {
  const idx = join(process.env.SQLI_LEDGER_DIR, 'index.jsonl');
  const rows = readFileSync(idx, 'utf-8')
    .split('\n')
    .filter(Boolean)
    .map((l) => { try { return JSON.parse(l); } catch { return null; } })
    .filter(Boolean);
  return rows.slice(-limit).reverse();
}

/** 在隔离台账目录里跑一段断言，结束后恢复 env 并清目录 */
function withLedger(content, fn) {
  const dir = mkdtempSync(join(tmpdir(), 'sqli-ledger-list-'));
  const prev = process.env.SQLI_LEDGER_DIR;
  process.env.SQLI_LEDGER_DIR = dir;
  mkdirSync(dir, { recursive: true });
  if (content !== null) writeFileSync(join(dir, 'index.jsonl'), content, 'utf-8');
  try {
    return fn();
  } finally {
    if (prev === undefined) delete process.env.SQLI_LEDGER_DIR;
    else process.env.SQLI_LEDGER_DIR = prev;
    try { rmSync(dir, { recursive: true, force: true }); } catch { /* ignore */ }
  }
}

const row = (id) => JSON.stringify({ scanId: `s${id}`, target: { url: `http://t/${id}` }, riskLevel: 'Low' });

/** 断言新旧输出逐条一致（用 JSON 串比对，避免深比较的键序噪声） */
function assertSame(content, limits) {
  withLedger(content, () => {
    for (const limit of limits) {
      const a = oldListScans(limit);
      const b = listScans(limit);
      assert.deepEqual(b, a, `limit=${limit}`);
    }
  });
}

// ── §A 基本形态 ─────────────────────────────────────────────────────────────
test('§A 十行取三条：尾部三条、新→旧', () => {
  const lines = Array.from({ length: 10 }, (_, i) => row(i)).join('\n') + '\n';
  withLedger(lines, () => {
    const got = listScans(3);
    assert.equal(got.length, 3);
    assert.equal(got[0].scanId, 's9');
    assert.equal(got[2].scanId, 's7');
    assert.deepEqual(got, oldListScans(3));
  });
});

test('§A limit 大于总行数：全量倒序', () => {
  const lines = Array.from({ length: 5 }, (_, i) => row(i)).join('\n') + '\n';
  assertSame(lines, [5, 50, 1000]);
});

test('§A 空索引文件与缺失索引', () => {
  withLedger('', () => {
    assert.deepEqual(listScans(10), []);
    assert.deepEqual(listScans(10), oldListScans(10));
  });
  withLedger(null, () => {
    assert.deepEqual(listScans(10), []);
  });
});

// ── §B 脏行形态（旧实现靠 filter(Boolean) 丢弃 / catch 跳过） ───────────────
test('§B 空行 / 坏 JSON / null / 0 / false 行：跳过且不中断', () => {
  const lines = [
    row(0),
    '',
    '{坏 JSON',
    'null',
    '0',
    'false',
    row(1),
    '   ',
    row(2),
  ].join('\n') + '\n';
  assertSame(lines, [1, 2, 3, 50]);
  withLedger(lines, () => {
    const got = listScans(3);
    assert.deepEqual(got.map((r) => r.scanId), ['s2', 's1', 's0']);
  });
});

test('§B 文件末尾无换行：最后一行仍算登记', () => {
  const content = `${row(0)}\n${row(1)}`; // 末尾没有 \n
  assertSame(content, [1, 2, 50]);
});

test('§B CRLF 行尾：解析结果与旧实现一致', () => {
  const content = `${row(0)}\r\n${row(1)}\r\n${row(2)}\r\n`;
  assertSame(content, [1, 2, 3]);
});

test('§B 只有一行、且无换行', () => {
  assertSame(row(42), [1, 5, 50]);
  withLedger(row(42), () => assert.equal(listScans(1)[0].scanId, 's42'));
});

// ── §C 旧实现的 slice(-limit) 反直觉语义 ────────────────────────────────────
test('§C limit=0 ⇒ 全量（slice(-0) === slice(0)），不是空数组', () => {
  const lines = Array.from({ length: 6 }, (_, i) => row(i)).join('\n') + '\n';
  withLedger(lines, () => {
    const got = listScans(0);
    assert.equal(got.length, 6, 'limit=0 必须返回全部（旧语义）');
    assert.deepEqual(got, oldListScans(0));
  });
});

test('§C 负 limit ⇒ 从第 |limit| 条起取，与旧实现一致', () => {
  const lines = Array.from({ length: 8 }, (_, i) => row(i)).join('\n') + '\n';
  assertSame(lines, [-1, -3, -8, -20]);
});

// ── §D 确定性随机对照 ───────────────────────────────────────────────────────
test('§D 500 行混合语料 × 5 档 limit：与 oracle 逐条一致', () => {
  let s = 20261102 >>> 0;
  const rnd = () => ((s = (s * 1664525 + 1013904223) >>> 0) / 0x100000000);
  const parts = [];
  for (let i = 0; i < 500; i++) {
    const r = rnd();
    if (r < 0.05) parts.push(''); // 空行
    else if (r < 0.08) parts.push('{oops'); // 坏行
    else if (r < 0.10) parts.push('null'); // falsy 行
    else parts.push(row(i));
  }
  const content = parts.join('\n') + '\n';
  assertSame(content, [1, 7, 50, 500, 1000]);
});

// ── §E 规模化：尾部截取必须真的只解析尾部 ───────────────────────────────────
test('§E 15605 行索引上 limit=50 的结果与全量解析一致', () => {
  const lines = Array.from({ length: 15605 }, (_, i) => row(i)).join('\n') + '\n';
  assertSame(lines, [50]);
});

// ── §F 尾块容量边界：行很长时要扩容，不能少给 ───────────────────────────────
test('§F 每行 ~4KB 的 2MB 索引：limit 超过首块容量仍要凑齐', () => {
  // 首块 1MB 约 250 行 < limit=400 ⇒ 必须扩容再读，否则会少返回
  const pad = 'x'.repeat(4000);
  const lines = Array.from({ length: 600 }, (_, i) => JSON.stringify({ scanId: `s${i}`, pad })).join('\n') + '\n';
  assert.ok(lines.length > 1024 * 1024, '语料必须大于首块，否则测不到扩容');
  assertSame(lines, [400, 50]);
});

test('§F 超长单行（> 首块）也不崩，退化全量读后仍正确', () => {
  const pad = 'y'.repeat(2 * 1024 * 1024);
  const content = `${JSON.stringify({ scanId: 'big', pad })}\n${JSON.stringify({ scanId: 'small' })}\n`;
  assertSame(content, [1, 2]);
});

// ── §G UTF-8 多字节被块边界切断 ────────────────────────────────────────────
test('§G 中文行跨块边界：不得出现替换字符污染，结果与 oracle 一致', () => {
  // 每行中文约占 3 字节，构造使 1MB 边界必然落在某行中间
  const zh = '中文目标扫描记录';
  const lines = Array.from({ length: 20000 }, (_, i) => JSON.stringify({ scanId: `s${i}`, target: { url: `http://例${i}.测试/${zh}` } })).join('\n') + '\n';
  assert.ok(lines.length > 1024 * 1024);
  assertSame(lines, [10, 200, 2000]);
  // 结果里不得出现 UTF-8 截断产生的替换字符
  withLedger(lines, () => {
    for (const r of listScans(200)) assert.ok(!String(r.target.url).includes('\uFFFD'));
  });
});
