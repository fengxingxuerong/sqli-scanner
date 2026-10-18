// ============================================================================
// tests/tamperLiteralWalk.guard.test.js —— 迁移守卫：已迁移插件不得回退（D57 5.4 / D107 硬化）
//
// 断言 server/src/core/tamper/plugins/*.js 中不得再出现手写字面量扫描的典型状态变量
//（inSingle/inDouble/inQuote/inStr；比对前剥离行注释，避免注释引用造成误报），
// 除显式白名单中的插件外。
//
// [D107 2026-10-18] 原正则只查 inSingle/inDouble，plus2concat/plus2fnconcat 用 inQuote、
// scalarselectinline 用 inStr，三处漏网（P1-4 侦察发现）。本批四个手写扫描插件迁移后
//（if2case / ifnull2casewhenisnull 走 maskLiterals，plus2 双胞胎走 onText 闭包），
// 把守卫扩到四变量全集，避免同类再生。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const pluginsUrl = new URL('../src/core/tamper/plugins/', import.meta.url);
const pluginsPath = fileURLToPath(pluginsUrl);

// 白名单（每条必须仍在正文里匹配四变量之一，「防腐烂」测试钉住）：
//   · space2comment —— 反引号 + 块注释五态机（literalWalk 只识别 ' 与 "，扩展属独立批次）
//   · space2morehash —— 两遍扫描（第一遍关键字聚合语义不同），literalWalk 单遍模型表达不了
//   · scalarselectinline —— 逃逸闭合符启发式 + 反引号 + 8 轮收敛（hasClosingQuote/isEscapeQuote
//     不是字面量分段语义；D107 已逐条评估，维持定制扫描并在此点名留痕）
const WHITELIST = new Set(['space2comment.js', 'space2morehash.js', 'scalarselectinline.js']);

const SCAN_VARS = /\binSingle\b|\binDouble\b|\binQuote\b|\binStr\b/;

/** 剥离 `//` 行注释后的源文本（守卫匹配用，注释中的引用不算回退）。 */
function stripLineComments(src) {
  return src
    .split('\n')
    .map((line) => {
      const i = line.indexOf('//');
      return i >= 0 ? line.slice(0, i) : line;
    })
    .join('\n');
}

test('已迁移插件不得再出现手写扫描状态变量（防回退）', () => {
  const files = readdirSync(pluginsPath).filter((f) => f.endsWith('.js'));
  assert.ok(files.length > 0, 'plugins 目录不应为空');

  const violations = [];
  for (const f of files) {
    const src = stripLineComments(readFileSync(new URL(f, pluginsUrl), 'utf8'));
    if (SCAN_VARS.test(src) && !WHITELIST.has(f)) {
      violations.push(f);
    }
  }
  assert.deepEqual(violations, [], `以下插件不应再含手写扫描状态变量：${violations.join(', ')}`);
});

test('白名单中的插件确实仍含手写扫描状态变量（防白名单腐烂）', () => {
  for (const f of WHITELIST) {
    const src = stripLineComments(readFileSync(new URL(f, pluginsUrl), 'utf8'));
    assert.ok(SCAN_VARS.test(src), `${f} 在白名单中但已不含手写扫描状态变量 —— 应从白名单移除`);
  }
});
