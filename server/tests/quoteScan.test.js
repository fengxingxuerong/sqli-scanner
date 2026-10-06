// ============================================================================
// tests/quoteScan.test.js —— 字面量扫描单一真源的自测
//
// quoteScan.js 是 2026-10-05 新抽出的：此前同一判据（转义奇偶性 + 字面量边界）
// 在 tamper/plugins/ 里重复了 23 个文件、47 处，且每一处都是错的。
// 既然它成了单一真源，**它自己的正确性必须被直接钉住** ——
// 否则只是把 23 份错误实现换成 1 份错误实现。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isQuoteEscaped, readSqlLiteral, splitByLiteral } from '../src/core/tamper/quoteScan.js';

test('转义-1) 奇偶性判据（不是"前一个字符是不是反斜杠"）', () => {
  const odd = "a\\'";    // 1 个反斜杠 ⇒ 转义
  const even = "a\\\\'";  // 2 个 ⇒ 未转义
  assert.equal(isQuoteEscaped(odd, odd.length - 1), true, '单反斜杠 ⇒ 被转义');
  assert.equal(isQuoteEscaped(even, even.length - 1), false, '双反斜杠 ⇒ 未被转义');
  const three = "a\\\\\\'"; // 3 个 ⇒ 奇数 ⇒ 转义
  assert.equal(isQuoteEscaped(three, three.length - 1), true, '三反斜杠 ⇒ 被转义');
});

test('转义-2) 下标 0 处无前驱字符 ⇒ 不算转义', () => {
  assert.equal(isQuoteEscaped("'", 0), false);
  assert.equal(isQuoteEscaped('"', 0), false);
});

test('读取-3) 正常字面量返回 body 与闭引号位置', () => {
  const lit = readSqlLiteral("'admin'", 0, "'");
  assert.equal(lit.closed, true);
  assert.equal(lit.body, 'admin');
  assert.equal(lit.end, 6);
});

test('读取-4) 未闭合字面量必须 closed=false（契约的关键）', () => {
  const lit = readSqlLiteral("'unterminated", 0, "'");
  assert.equal(lit.closed, false,
    '未闭合必须显式标记 —— 调用方据此放弃编码，绝不能产出半截 0xHEX');
  assert.equal(lit.body, 'unterminated');
});

test('读取-5) 转义引号不作为闭引号', () => {
  const s = "'x\\' AND 1";
  const lit = readSqlLiteral(s, 0, "'");
  assert.equal(lit.closed, false, `单反斜杠后引号未闭合，实际 closed=${lit.closed}`);
  const s2 = "'x\\\\' AND 1";
  const lit2 = readSqlLiteral(s2, 0, "'");
  assert.equal(lit2.closed, true, '双反斜杠后引号闭合');
  assert.equal(lit2.body, 'x\\\\', '字面量内容保留两个反斜杠');
});

test('分段-6) text / literal 交替，未闭合段标 closed=false', () => {
  const segs = splitByLiteral("CONCAT('ab','cd')", "'");
  assert.deepEqual(segs.map((s) => [s.kind, s.text]), [
    ['text', 'CONCAT('],
    ['literal', 'ab'],
    ['text', ','],
    ['literal', 'cd'],
    ['text', ')'],
  ], '实际: ' + JSON.stringify(segs.map((s) => [s.kind, s.text])));
  assert.ok(segs.filter((s) => s.kind === 'literal').every((s) => s.closed));
});

test('分段-7) 未闭合时其后内容并入最后一个 literal 段并标 false', () => {
  const segs = splitByLiteral("SELECT 'abc AND SLEEP(5)", "'");
  const last = segs[segs.length - 1];
  assert.equal(last.kind, 'literal');
  assert.equal(last.closed, false, '未闭合段必须标 false');
  assert.equal(last.text, 'abc AND SLEEP(5)', '未闭合段应含其后的全部内容');
});

test('分段-8) 无字面量 / 空串 / 纯引号的退化输入', () => {
  assert.deepEqual(splitByLiteral('SELECT 1', "'"), [{ kind: 'text', text: 'SELECT 1', closed: true }]);
  assert.deepEqual(splitByLiteral('', "'"), []);
  assert.doesNotThrow(() => splitByLiteral("'", "'"));
  assert.doesNotThrow(() => splitByLiteral("''", "'"));
});

test('分段-9) 双引号同样适用（不能只处理单引号）', () => {
  const segs = splitByLiteral('SELECT "admin" FROM t', '"');
  assert.deepEqual(segs.map((s) => [s.kind, s.text]), [
    ['text', 'SELECT '],
    ['literal', 'admin'],
    ['text', ' FROM t'],
  ]);
});

test('自证-10) 奇偶两种输入必须产出不同分段（挡"判据被删掉"）', () => {
  const odd = splitByLiteral("'x\\' AND 1", "'");
  const even = splitByLiteral("'x\\\\' AND 1", "'");
  assert.notDeepEqual(odd, even,
    '奇/偶反斜杠必须产出不同分段 —— 相同即说明转义判别已失效（哪怕方向反了）');
});
