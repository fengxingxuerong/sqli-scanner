// ============================================================================
// tests/tamperLiteralWalk.guard.test.js —— 迁移守卫：已迁移插件不得回退（D57 5.4）
//
// 断言 server/src/core/tamper/plugins/*.js 中不得再出现 inSingle/inDouble 标识符
//（除显式白名单中的未迁移复杂插件）。
// 后续迁移白名单中的插件时，从白名单中移除即可。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const pluginsUrl = new URL('../src/core/tamper/plugins/', import.meta.url);
const pluginsPath = fileURLToPath(pluginsUrl);

// [D57 第二阶段] 21 个插件已迁移到 walkLiterals（onText/onLiteral 回调），
// 从白名单移除。保留的 4 个是「多遍结构定位/反引号/块注释/关键字聚合」类，
// 其循环目的不是字面量分段，超出 literalWalk 语义，不迁：
//   · if2case / ifnull2casewhenisnull —— while 多遍 + 括号深度定位函数参数
//   · space2comment —— 反引号 + 块注释状态（literalWalk 不支持，扩展属独立批次）
//   · space2morehash —— 两遍扫描（关键字聚合 + 空格替换），第一遍语义不同
const WHITELIST = new Set([
  'if2case.js',
  'ifnull2casewhenisnull.js',
  'space2comment.js',
  'space2morehash.js',
]);

test('已迁移插件不得再出现 inSingle/inDouble（防回退）', () => {
  const files = readdirSync(pluginsPath).filter((f) => f.endsWith('.js'));
  assert.ok(files.length > 0, 'plugins 目录不应为空');

  const violations = [];
  for (const f of files) {
    const src = readFileSync(new URL(f, pluginsUrl), 'utf8');
    if (/\binSingle\b|\binDouble\b/.test(src) && !WHITELIST.has(f)) {
      violations.push(f);
    }
  }
  assert.deepEqual(violations, [], `以下插件不应再含 inSingle/inDouble：${violations.join(', ')}`);
});

test('白名单中的插件确实仍含 inSingle/inDouble（防白名单腐烂）', () => {
  for (const f of WHITELIST) {
    const src = readFileSync(new URL(f, pluginsUrl), 'utf8');
    assert.ok(/\binSingle\b|\binDouble\b/.test(src),
      `${f} 在白名单中但已不含 inSingle/inDouble —— 应从白名单移除`);
  }
});