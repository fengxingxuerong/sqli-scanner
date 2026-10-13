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

const WHITELIST = new Set([
  'backslash2forward.js',
  'bin2ascii.js',
  'brotli.js',
  'char2ascii.js',
  'char2hex.js',
  'coffee.js',
  'compression.js',
  'css.js',
  'djson.js',
  'dpayload.js',
  'gzip.js',
  'hex2ascii.js',
  'if2case.js',
  'ifnull2casewhenisnull.js',
  'jsonescape.js',
  'lpad.js',
  'noequals.js',
  'randomcaseall.js',
  'reversestring.js',
  'space2comment.js',
  'space2morehash.js',
  'str2hex.js',
  'string2binary.js',
  'string2hexall.js',
  'unparen.js',
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