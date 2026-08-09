// v10 新增 tamper 插件（hex2char / charunicodeasciiencode）回归测试
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { tamperRegistry } from '../src/core/tamper/index.js';
import { obfuscateWithConfig } from '../src/core/tamper/applyTampers.js';
import { hex2char } from '../src/core/tamper/plugins/hex2char.js';
import { charunicodeasciiencode } from '../src/core/tamper/plugins/charunicodeasciiencode.js';

test('v10 两个新插件已注册到 tamperRegistry', () => {
  assert.ok(tamperRegistry.get('hex2char'), 'hex2char 应已注册');
  assert.ok(tamperRegistry.get('charunicodeasciiencode'), 'charunicodeasciiencode 应已注册');
});

test('charunicodeasciiencode 将 ASCII 转为 \\uXXXX', () => {
  assert.equal(charunicodeasciiencode.transform("'"), "\\u0027");
  assert.equal(charunicodeasciiencode.transform('1'), '\\u0031');
  // 非 ASCII 原样保留
  assert.equal(charunicodeasciiencode.transform('中'), '中');
});

test('hex2char 仅对 MySQL/MariaDB 生效，拼为 CONCAT(CHAR(...))', () => {
  const ctxMy = { dbms: 'MySQL' };
  const out = hex2char.transform("1'", ctxMy);
  assert.ok(out.startsWith('CONCAT(') && out.includes('CHAR(49)') && out.includes('CHAR(39)'), `输出应含 CHAR 拼接，实际 ${out}`);
  // 非 MySQL 系原样返回
  assert.equal(hex2char.transform("1'", { dbms: 'PostgreSQL' }), "1'");
});

test('obfuscateWithConfig 链式调用 v10 插件生效', () => {
  const ctx = {
    dbms: 'MySQL',
    config: { wafEvasion: { tamper: { enabled: true, plugins: ['charunicodeasciiencode'], intensity: 'medium' } } },
  };
  const out = obfuscateWithConfig("' OR '1'='1", ctx);
  assert.equal(out, "\\u0027\\u0020\\u004F\\u0052\\u0020\\u0027\\u0031\\u0027\\u003D\\u0027\\u0031");
});
