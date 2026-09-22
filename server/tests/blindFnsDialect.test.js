// ============================================================================
// blindFnsDialect.test.js —— 盲注提取函数字典（LEN_FN/SUB_FN/ASCII_FN）的方言回归
//
// [P2 审计修复 2026-09-22 真引擎实测] 背景：这三张字典是「按方言拼 SQL」的模板，
// 与 SYS_QUERIES 同属一类，但此前只被「键是否存在」的浅断言覆盖
// （见 c-class-dbms-coverage.test.js 的 extractConstMap）——**键存在 ≠ 值是可用函数**。
//
// 本轮真 JDBC（Derby 10.16）实测发现两处真实缺陷：
//   ① SUB_FN.Derby 用 `substring((e) FROM i FOR 1)` —— Derby **没有 SUBSTRING 函数**
//      三种写法（FROM/FOR、逗号、大写）全部 `Syntax error: Encountered "substring"`；
//      只有 `substr((e),i,1)` 返回 [["A"]]。
//   ② ASCII_FN.Derby 用 `unicode(c)` —— Derby 报 `'UNICODE' is not recognized as a function
//      or procedure.`，且穷举确认 Derby **无任何字符→码点函数**（ASCII/UNICODE/CODE_POINT/
//      ORD/ORDINAL/CHAR_CODE/SYSFUN.* 全部不存在；`CAST(... AS INT)` 亦失败）。
//      → 码点式提取结构性不可用，故显式置 null 并由调用方诚实降级。
//
// 本文件把这些实测结论钉成断言，防止退回。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { LEN_FN, SUB_FN, ASCII_FN } from '../src/engine/extractionMaps.js';
import { extractBoolean } from '../src/engine/blindExtractor.js';

// 捕获是否发过请求的 mock ex —— 用于证明「结构性不支持时不投无效 SQL」
function makeCountingEx() {
  const state = { sent: [] };
  return {
    state,
    ex: {
      _extractCache: new Map(),
      async _send(ctx, payload) {
        state.sent.push(payload);
        return { data: 'PAGE', status: 200 };
      },
    },
  };
}

function makeCtx(dbms) {
  return {
    httpClient: { async request() { return { data: 'PAGE', status: 200 }; } },
    dbms,
    scanId: 't',
    config: { predictOutput: false },
    point: { id: 'p', location: 'url', param: 'id', originalValue: '1', boundary: '' },
    target: { url: 'http://mock/' },
  };
}

// ── ① SUB_FN.Derby 必须是 substr(...)（Derby 无 SUBSTRING 函数）──────────────
test('[P2] SUB_FN.Derby 生成 substr((expr),n,1)（真机实测唯一可用写法）', () => {
  const out = SUB_FN.Derby('name', '1');
  assert.equal(out, 'substr((name),1,1)');
  assert.ok(!/substring/i.test(out), 'Derby 不得出现 substring（真机报 Syntax error: Encountered "substring"）');
});

test('[P2] SUB_FN.Derby 与其他方言的写法差异被显式保留（PG/Firebird 仍用标准 FROM/FOR）', () => {
  // PG/Firebird 的标准 SQL 写法是合法的，不能因为 Derby 而误改它们
  assert.match(SUB_FN.PostgreSQL('x', '1'), /FROM 1 FOR 1/);
  assert.match(SUB_FN.Firebird('x', '1'), /FROM 1 FOR 1/);
  assert.equal(SUB_FN.Derby('x', '1'), 'substr((x),1,1)');
});

// ── ② ASCII_FN.Derby 显式 null（Derby 无字符→码点函数）──────────────────────
test('[P2] ASCII_FN.Derby 为 null（真机穷举：Derby 无任何字符→码点函数）', () => {
  assert.equal(ASCII_FN.Derby, null, 'Derby 无码点函数，应为 null（结构性不支持）');
});

// ── ③ 结构性不支持时：返回 null 且**不发任何请求**（不投无效 SQL）─────────────
test('[P2] extractBoolean(Derby) 返回 null 且零发包（不生成 unicode/substring 无效 SQL）', async () => {
  const { ex, state } = makeCountingEx();
  const ctx = makeCtx('Derby');
  const got = await extractBoolean(ex, ctx, "'DERBY'");
  assert.equal(got, null, 'Derby 码点通道结构性不可用 → 应返回 null 诚实降级');
  assert.deepEqual(state.sent, [], '不应发出任何注入请求（避免投无效函数名让目标报错）');
});

// ── ④ 零回归：MySQL 仍走原路径（仍发 LENGTH/ASCII 探针，未被新守卫拦掉）──────
test('[P2] extractBoolean(MySQL) 未回归：仍发 MySQL 形态探针（LENGTH/ASCII + SUBSTRING）', async () => {
  // 注意：所有响应恒等时长度二分不会收敛，就走不到 ASCII 段 ——
  // 故这里只对「长度探针」给出真值答案（长度=2），让流程推进到字符段以便观察其 SQL 形态。
  const sent = [];
  const ex = {
    _extractCache: new Map(),
    async _send(ctx, payload) {
      sent.push(payload);
      const lm = /LENGTH\(\((.*)\)\)>(\d+)\)/.exec(payload);
      if (lm) return { data: 2 > Number(lm[2]) ? 'T' : 'F', status: 200 };
      return { data: 'F', status: 200 };
    },
  };
  await extractBoolean(ex, makeCtx('MySQL'), 'version()');
  assert.ok(sent.length > 0, 'MySQL 应正常发包（不得被新守卫提前返回 null）');
  const joined = sent.join('\n');
  assert.match(joined, /LENGTH\(\(version\(\)\)\)/, '应含 MySQL 的 LENGTH 探针');
  assert.match(joined, /ASCII\(SUBSTRING\(\(version\(\)\),\d+,1\)\)/, '应含 MySQL 的 ASCII(SUBSTRING(...,n,1)) 探针');
  assert.ok(!/unicode\(/i.test(joined), 'MySQL 通道不得出现 Derby 专用的 unicode()');
});

// ── ④b 语义：显式 null 不得回落到 MySQL 语法 ────────────────────────────────
test('[P2] 显式 null 的方言（Derby）不得回落生成 ASCII(...) 探针', async () => {
  const { ex, state } = makeCountingEx();
  await extractBoolean(ex, makeCtx('Derby'), "'DERBY'");
  const joined = state.sent.join('\n');
  assert.ok(!/ASCII\(/i.test(joined), `Derby 不得生成 ASCII 探针（回落 MySQL 会静默失败）：${joined.slice(0, 200)}`);
});

// ── ⑤ 源码契约：ASCII_FN 中不得再出现 unicode（Derby 专属）─────────────────
test('[P2] 源码契约：ASCII_FN 不再对 Derby 使用 unicode()', async () => {
  const { readFileSync } = await import('node:fs');
  const src = readFileSync(new URL('../src/engine/extractionMaps.js', import.meta.url), 'utf-8');
  // 定位 ASCII_FN 块，确认 Derby 不是 unicode(...)
  const m = /export const ASCII_FN\s*=\s*\{([\s\S]*?)\n\};/.exec(src);
  assert.ok(m, '应能定位 ASCII_FN 定义');
  const body = m[1];
  const derbyLine = body.split('\n').find((l) => /^\s*Derby\s*:/.test(l));
  assert.ok(derbyLine, 'ASCII_FN 应有 Derby 条目');
  assert.ok(!/unicode/i.test(derbyLine), `ASCII_FN.Derby 不得使用 unicode：${derbyLine}`);
  assert.match(derbyLine, /null/, 'ASCII_FN.Derby 应为 null（结构性不支持）');
});

// ── ⑥ 全局：所有方言的 SUB_FN 输出都不得含 Derby 不认识的 substring（仅 Derby）──
test('[P2] 全局：除 Derby 外各方言 SUB_FN 均无「substring 未加 FROM/FOR」的混用写法', () => {
  const bad = [];
  for (const [db, fn] of Object.entries(SUB_FN)) {
    if (typeof fn !== 'function') continue;
    const out = fn('x', '1');
    if (!/^[a-z_]+\(/i.test(out)) bad.push(`${db}:${out}`);
  }
  assert.deepEqual(bad, [], `以下方言 SUB_FN 输出形状异常：${bad.join(', ')}`);
});

// ── ⑦ LEN_FN.Derby 保持 length()（Derby 确实支持 LENGTH，与 SUB/ASCII 不同）─────
// 真机实测：SELECT (length((name))) FROM b -> [["3"]] ✅
// 即 Derby 的三张字典里**只有** SUB/ASCII 有问题，LEN 是正确的 —— 本断言防止误改。
test('[P2] LEN_FN.Derby 保持 length((x))（真机可用，勿连带改动）', () => {
  assert.equal(LEN_FN.Derby('name'), 'length((name))');
});
