// ============================================================================
// tests/string2hexall.test.js —— 字面量编码的闭合性与转义奇偶性
//
// ── 存在理由 ────────────────────────────────────────────────────────────────
// 2026-10-05 扫转义判别式时发现本文件（插件）的三个真实缺陷：
//
// ① **未闭合字面量吞掉后续内容并产出非法 SQL**（最重）
//    j 循环走完仍未遇到闭引号时，i 停在 src.length、str 攒了剩余全部字符，
//    然后照常输出 0x<hex>：既丢了开引号，又把后面的 ` AND SLEEP(5)` 编码进去。
//      修前：`SELECT 'unterminated` → `SELECT 0x756e…74unterminated`（语法错误）
//      修后：`SELECT 'unterminated` → `SELECT 'unterminated`（原样透出）
//    WAF 一旦拦掉带引号的 payload，tamper 链正需要它**继续可用**，不能改坏。
//
// ② **转义判别只看前一个字符**（同型缺陷在本目录 24 个插件 47 处出现）
//    `src[j-1] !== '\\'` 不是判据，连续反斜杠的**奇偶性**才是。
//
// ③ **prev = src[i-1] 跨轮次失效**
//    内层循环把 i 推到闭引号后，src[i-1] 指向的是字面量内容最后一个字符而非闭引号，
//    外层引号判断与实际状态脱节：
//      修前：`'a'b'c'` → `0x61b'c0x`（第二个 'a' 丢失）
//      修后：`'a'b'c'` → `0x61b0x63`
//
// 本文件逐条钉住，并显式区分"该编码"与"不该编码"两种期望 ——
// 只钉前者会让人以为统一都该编码，从而把判据改反。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { string2hexall } from '../src/core/tamper/plugins/string2hexall.js';

test('闭合性-1) 每个字面量都被编码，且闭引号不会丢失', () => {
  // 修前：`CONCAT('ab','cd')` → `CONCAT(0x6162,'cd0x29)`（闭引号消失、括号被编码）
  assert.equal(string2hexall.transform("CONCAT('ab','cd')", {}), 'CONCAT(0x6162,0x6364)');
  assert.equal(string2hexall.transform("SELECT 'admin' FROM t", {}), 'SELECT 0x61646d696e FROM t');
  assert.equal(string2hexall.transform("'ab' AND SLEEP(5)", {}), '0x6162 AND SLEEP(5)',
    '字面量之后的注入部分必须原样保留（这是 payload 的主体）');
});

test('闭合性-2) 未闭合字面量**原样透出**，绝不产出半截 0xHEX', () => {
  // 修前：SELECT 'unterminated → SELECT 0x756e7465726d696e61746564unterminated（语法错误）
  assert.equal(string2hexall.transform("SELECT 'unterminated", {}), "SELECT 'unterminated");
  assert.equal(string2hexall.transform('AND 1=1 -- \'', {}), "AND 1=1 -- '");
  // 关键判据：输出里不能出现"编码了内容却没有引号包裹"的形态
  const out = string2hexall.transform("SELECT 'x", {});
  assert.ok(!/0x[0-9a-f]+[a-z]/i.test(out) || out.includes("'"),
    `未闭合时不应产出裸露的 0xHEX：${out}`);
});

test('闭合性-3) 相邻字面量不串味（prev 缓存失效的回归）', () => {
  // 修前：'a'b'c' → 0x61b'c0x（第二个 'a' 丢失）
  assert.equal(string2hexall.transform("'a'b'c'", {}), '0x61b0x63');
  assert.equal(string2hexall.transform("''", {}), '0x', '空字面量应编码为空 0x');
});

test('转义-4) 单反斜杠 ⇒ 引号被转义，字面量延续', () => {
  // `'x\'` 的闭引号被转义 ⇒ 后面没有闭引号 ⇒ 整个剩余串原样透出
  const out = string2hexall.transform("'x\\' AND SLEEP(5)", {});
  assert.equal(out, "'x\\' AND SLEEP(5)",
    `单反斜杠后引号未闭合，应原样透出，实际: ${out}`);
});

test('转义-5) 双反斜杠 ⇒ 引号闭合，后续内容继续被编码', () => {
  // 修前：CONCAT('x\\','cd') 的字面量边界错乱
  const out = string2hexall.transform("CONCAT('x\\\\','cd')", {});
  assert.equal(out, "CONCAT(0x785c5c,0x6364)",
    `双反斜杠后引号闭合，两个字面量都该被编码，实际: ${out}`);
});

test('自证-6) 奇偶两种反斜杠必须产出**不同**结果（挡"判据被删掉"）', () => {
  const odd = string2hexall.transform("'x\\' AND 1", {});
  const even = string2hexall.transform("'x\\\\' AND 1", {});
  assert.notEqual(odd, even,
    '奇/偶反斜杠必须产出不同结果 —— 相同即说明转义判别已失效（哪怕方向反了）');
});

test('边界-7) 双引号字面量同样适用（不能只修单引号）', () => {
  assert.equal(string2hexall.transform('SELECT "admin"', {}), 'SELECT 0x61646d696e');
  assert.equal(string2hexall.transform('SELECT "unterminated', {}), 'SELECT "unterminated');
});

test('边界-8) 无字面量时原样返回（不改写）', () => {
  assert.equal(string2hexall.transform('SELECT 1 FROM t', {}), 'SELECT 1 FROM t');
  assert.equal(string2hexall.transform('', {}), '');
});

test('边界-9) 非字符串输入不抛错（tamper 链会喂各种形态）', () => {
  for (const bad of [null, undefined, 123, {}]) {
    assert.doesNotThrow(() => string2hexall.transform(bad, {}), `(${String(bad)}) 抛错`);
  }
});

test('边界-10) 0xHEX 可还原且为合法 SQL 字面量（MySQL/MSSQL 语义）', () => {
  const out = string2hexall.transform("'admin'", {});
  assert.equal(out, '0x61646d696e');
  assert.equal(Buffer.from(out.slice(2), 'hex').toString('utf8'), 'admin');
});
