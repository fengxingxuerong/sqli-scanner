// [P1-PERF 2026-11-02] 有界正文匹配：窗口截断不能漏掉边界/末尾的签名。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { matchBounded, hasBoundedMatch } from '../src/core/boundedMatch.js';

const SIG = /SQL syntax|ORA-\d{5}|extractvalue/i;

test('小文本直接匹配（与 String.match 同义）', () => {
  const m = matchBounded('x'.repeat(10) + 'ORA-00933' + 'y'.repeat(10), SIG);
  assert.ok(m);
  assert.equal(m[0], 'ORA-00933');
});

test('签名在 2MB 文本末尾：窗口轮转仍能命中', () => {
  const text = 'x'.repeat(2 * 1024 * 1024) + 'SQL syntax error';
  assert.ok(matchBounded(text, SIG, { windowChars: 64 * 1024, overlap: 256 }));
});

test('签名跨窗口边界：overlap 回读避免漏匹配', () => {
  const w = 4096;
  const text = 'a'.repeat(w - 10) + 'extractvalue(1,concat(0x7e,version()))' + 'b'.repeat(20);
  assert.ok(matchBounded(text, SIG, { windowChars: w, overlap: 64 }));
});

test('无命中时返回 null / false（大文本不会误报）', () => {
  assert.equal(matchBounded('x'.repeat(1024 * 1024), SIG, { windowChars: 64 * 1024 }), null);
  assert.equal(hasBoundedMatch('x'.repeat(1024 * 1024), SIG, { windowChars: 64 * 1024 }), false);
});

test('g/y 标志不影响多次调用（lastIndex 不串味）', () => {
  const re = /SQL syntax/gi;
  assert.ok(matchBounded('SQL syntax', re));
  assert.equal(matchBounded('nope', re), null);
  assert.ok(matchBounded('SQL syntax', re));
});
