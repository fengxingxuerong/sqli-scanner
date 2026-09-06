// CLI 交互式 shell 参数语义回归（[P2-FIX 2026-09-05]）
// --sql-shell/--os-shell：不带值（或值以 -- 开头）= true（REPL 模式）；带值 = 字符串（单次执行）
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseArgs } from '../bin/cli.js';

test('parseArgs: --sql-shell 不带值 → true（REPL 模式）', () => {
  const a = parseArgs(['-u', 'http://t/?id=1', '--sql-shell']);
  assert.equal(a.sqlShell, true);
});

test('parseArgs: --sql-shell 带值 → 字符串（单次执行，兼容旧语义）', () => {
  const a = parseArgs(['-u', 'http://t/?id=1', '--sql-shell', 'SELECT 1']);
  assert.equal(a.sqlShell, 'SELECT 1');
});

test('parseArgs: --os-shell 不带值 → true（REPL 模式）', () => {
  const a = parseArgs(['-u', 'http://t/?id=1', '--os-shell']);
  assert.equal(a.osShell, true);
});

test('parseArgs: --os-shell 后跟另一个开关 → 仍为 true（不吞参数）', () => {
  const a = parseArgs(['-u', 'http://t/?id=1', '--os-shell', '--authorized']);
  assert.equal(a.osShell, true);
  assert.equal(a.authorized, true);
});

test('parseArgs: --os-cmd 仍为必带值参数（兼容不变）', () => {
  const a = parseArgs(['-u', 'http://t/?id=1', '--os-cmd', 'whoami']);
  assert.equal(a.osCmd, 'whoami');
});

test('parseArgs: --udf-install + --udf-hex <path>', () => {
  const a = parseArgs(['-u', 'http://t/?id=1', '--udf-install', '--udf-hex', '/path/lib.so_']);
  assert.equal(a.udfInstall, true);
  assert.equal(a.udfHex, '/path/lib.so_');
});
