// [D241 对标 sqlmap --sql-file] CLI 解析层的判据
//
// 只钉两件事：
//   ① `--sql-file <path>` 能被解析出来（否则 cli.js 的 prepareScan 永远拿不到它）；
//   ② 未传时是 null（不是 undefined 的偶然值）——`prepareScan` 用 `if (args.sqlFile)` 判空，
//      两种 falsy 都能过，但显式 null 让 `--save-config` 的「非默认参数增量」口径稳定。
// 执行路径（读文件 → sqlShell → exploiter.sqlShell）由既有 exploit 测试覆盖，这里不重复造。
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { parseArgs } from '../bin/cli/args.js';

test('--sql-file 被解析进 args.sqlFile', () => {
  const a = parseArgs(['--sql-file', 'queries.sql']);
  assert.equal(a.sqlFile, 'queries.sql');
});

test('未传 --sql-file 时为 null（默认值口径稳定）', () => {
  const a = parseArgs([]);
  assert.equal(a.sqlFile, null);
});

test('--sql-file 与 --sql-shell 可共存（文件内容在 prepareScan 里覆盖串，解析层不做互斥）', () => {
  const a = parseArgs(['--sql-shell', 'SELECT 1', '--sql-file', 'q.sql']);
  assert.equal(a.sqlShell, 'SELECT 1');
  assert.equal(a.sqlFile, 'q.sql');
});
