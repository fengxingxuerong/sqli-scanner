// ============================================================================
// tests/space2morehash.test.js —— 引号感知的转义奇偶性
//
// ── 存在理由 ────────────────────────────────────────────────────────────────
// 2026-10-05 off-by-one/空值扫描时顺带发现：transform 判别"转义引号"用的是
//   `src[i-1] !== '\\'`（只看前一个字符）。
// 那是错的。真正的判据是**连续反斜杠的奇偶性**：
//   'a\'    1 个反斜杠 ⇒ 末位 ' 被转义，字符串**未闭合**
//   'a\\'   2 个反斜杠 ⇒ 末位 ' 未被转义，字符串**闭合**
// 原实现把后两种一律判成"被转义" ⇒ 遇到 'a\\' 后引号状态永不闭合，
// 于是该引号之后的所有字符都被当成字符串字面量：
//   · pass 1 不再给关键字追加混淆块 ⇒ AND / SLEEP **原样发出**，直接撞 WAF
//   · pass 2 的空格替换也一并失效
// MySQL / SQL Server 默认反斜杠转义，payload 里 'x\\' 极常见，不是边角情况。
//
// 本文件按"反斜杠个数"逐个钉住，并显式区分**该闭合**与**不该闭合**两种期望 ——
// 这是关键：只钉"单反斜杠"会让人以为统一都该闭合，从而把判据改反。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { space2morehash } from '../src/core/tamper/plugins/space2morehash.js';

/** 去掉随机串，保留可断言的结构（%23<字母数字>%0A → %23#%0A） */
function normalize(s) {
  return s.replace(/%23[A-Za-z]{6,12}%0A/g, '%23#%0A');
}

test('转义奇偶性-1) 双反斜杠后引号闭合 ⇒ 其后关键字必须继续混淆', () => {
  // 修复前：AND/SLEEP 原样发出
  const out = space2morehash.transform("SELECT * FROM t WHERE a='x\\\\' AND SLEEP(5)", {});
  const n = normalize(out);
  assert.match(n, /AND%23#%0A/, `双反斜杠后 AND 应被混淆，实际: ${n}`);
  assert.ok(!/\bAND\b(?!%23)/.test(n.replace(/AND%23#%0A/g, '')),
    `AND 不该原样出现，实际: ${n}`);
});

test('转义奇偶性-2) 单反斜杠后引号未闭合 ⇒ 其后内容属字面量，不混淆', () => {
  // 这不是缺陷，是正确语义：'x\' 的引号被转义，字符串延续到下一个 ' 之后。
  const out = space2morehash.transform("SELECT * FROM t WHERE a='x\\' AND SLEEP(5)", {});
  const n = normalize(out);
  assert.match(n, /AND\b/, `单反斜杠后 AND 属字面量，应保持原样，实际: ${n}`);
  assert.doesNotMatch(n, /AND%23#%0A/,
    `单反斜杠后引号未闭合，不该混淆 AND，实际: ${n}`);
});

test('转义奇偶性-3) 三反斜杠 ⇒ 奇数 ⇒ 引号未闭合（同单反斜杠）', () => {
  const out = space2morehash.transform("SELECT * FROM t WHERE a='x\\\\\\' AND SLEEP(5)", {});
  const n = normalize(out);
  assert.doesNotMatch(n, /AND%23#%0A/, `三反斜杠（奇数）引号未闭合，不该混淆 AND: ${n}`);
});

test('转义奇偶性-4) 无反斜杠的普通场景不受影响（修复未引入回归）', () => {
  const out = space2morehash.transform("SELECT * FROM t WHERE a='x' AND SLEEP(5)", {});
  const n = normalize(out);
  assert.match(n, /SELECT%23#%0A/, 'SELECT 应被混淆');
  assert.match(n, /AND%23#%0A/, `闭合引号后的 AND 应被混淆，实际: ${n}`);
});

test('转义奇偶性-5) 双引号同样适用（不能只修单引号）', () => {
  const out = space2morehash.transform('SELECT * FROM t WHERE a="x\\\\" AND SLEEP(5)', {});
  const n = normalize(out);
  assert.match(n, /AND%23#%0A/, `双引号场景 AND 应被混淆，实际: ${n}`);
});

test('自证-1) 修复未把判据改反：奇偶两种结果必须**不同**', () => {
  // 若两种输入产出相同输出，说明判据根本没生效（无论对错），
  // 这条断言专门挡"把整个引号逻辑删掉也能过测试"的退化实现。
  const odd = normalize(space2morehash.transform("a='x\\' AND 1", {}));
  const even = normalize(space2morehash.transform("a='x\\\\' AND 1", {}));
  assert.notEqual(odd, even,
    '奇/偶反斜杠必须产出不同结果 —— 相同即说明转义判别已失效');
  assert.match(even, /AND%23#%0A/, '偶数（闭合）应混淆');
  assert.doesNotMatch(odd, /AND%23#%0A/, '奇数（未闭合）不应混淆');
});

test('边界-2) 非字符串 / 空输入不抛错（tamper 链会喂各种形态）', () => {
  for (const bad of [null, undefined, '', 123, {}]) {
    assert.doesNotThrow(() => space2morehash.transform(bad, {}), `(${String(bad)}) 抛错`);
  }
  assert.equal(space2morehash.transform('', {}), '', '空串应原样返回');
});

test('边界-3) 只有引号 / 只有反斜杠等退化输入不产生未定义中间态', () => {
  for (const p of ["'", '"', '\\', "'\\", '\\"', 'SELECT']) {
    assert.doesNotThrow(() => space2morehash.transform(p, {}), `(${p}) 抛错`);
  }
});

test('边界-4) 引号内的空格不被替换（字面量完整性）', () => {
  const out = normalize(space2morehash.transform("SELECT 'a b c' FROM t", {}));
  assert.ok(out.includes("'a b c'"), `引号内空格应原样保留（否则破坏字符串语义）: ${out}`);
});
