// ============================================================================
// server/tests/cli.unknownFlags.test.js —— CLI 不得静默吞掉拼错的开关
// ============================================================================
// 起因（2026-09-25，做 CLI 直连 scope 时当场撞到）：`bin/cli/args.js` 的解析循环
// 原先是 `else { }` —— 无法识别的开关**静默忽略**。同文件对 --no-escape/--union-char
// 已明写「保留显式识别并给出可操作提示，避免用户以为传了没生效而反复排查」，
// 说明政策本就是"不许静默"，只是只覆盖了两个特例。
// 为什么这条值得钉死：代价落在红线上。同一个意图三种写法三种结果 ——
//   --driver sqlite  + --scope …  ⇒ 内嵌驱动放行（对）
//   --driver-type sqlite + --scope … ⇒ 开关被吞 ⇒ 当成未知主机拒（错，且看不出是拼写问题）
//   --scope-typo 10.20.0.0/16     ⇒ **红线整个消失，命令照常跑完、退出码 0**
// 最后一条是假安全：读的人以为限定了授权范围。
//
// 断言含**反向**一条：--no-escape / --union-char 属"已告知的未实现"，政策是告警但继续，
// 不能被这道硬拒一起吞进去（那会改变既有行为）。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { parseArgs, unknownFlagError } from '../bin/cli/args.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CLI = path.join(HERE, '..', 'bin', 'cli.js');

test('拼错的开关被记录，且 unknownFlagError 给出可操作文案', () => {
  const a = parseArgs(['-u', 'http://127.0.0.1:9/x', '--scope-typo', '10.20.0.0/16']);
  assert.deepEqual(a.unknownFlags, ['--scope-typo']);
  const err = unknownFlagError(a);
  assert.ok(err && /无法识别的参数/.test(err) && /--scope-typo/.test(err), `文案要点名开关：${err}`);
  // 关键：--scope 被吞掉 ⇒ args.scope 为空 ⇒ 红线确实没生效（这正是硬拒要防的事）
  assert.ok(!a.scope, '前提自检：拼错后 scope 真的为空（否则这条缺陷不成立）');
});

test('正常开关不误伤（含直连四件套）', () => {
  const a = parseArgs([
    '-d', 'mysql://root:pw@10.20.1.5:3306/db', '--driver', 'mysql',
    '--scope', '10.20.0.0/16', '--sql-template', 'SELECT 1 WHERE id={INJECT}',
    '--technique', 'UB', '--risk', '3',
  ]);
  assert.deepEqual(a.unknownFlags, [], `不该有未识别开关：${a.unknownFlags.join(',')}`);
  assert.equal(unknownFlagError(a), null);
  assert.equal(a.scope, '10.20.0.0/16');
});

test('已知但"未实现"的开关仍按原政策：告警但不计入硬拒', () => {
  const a = parseArgs(['-u', 'http://127.0.0.1:9/x', '--no-escape']);
  assert.deepEqual(a.unknownFlags, [], '--no-escape 已被显式识别（政策=告警后继续），不得当拼错');
  const b = parseArgs(['-u', 'http://127.0.0.1:9/x', '--union-char', 'X']);
  assert.deepEqual(b.unknownFlags, []);
});

test('裸位置参数不算开关（子命令/文件参数形态不被误判）', () => {
  const a = parseArgs(['ledger', 'list', '20']);
  assert.deepEqual(a.unknownFlags, []);
});

test('真起 CLI：拼错的开关 ⇒ 退出码非 0 且点名该开关（不只看函数，验入口接线）', () => {
  const r = spawnSync(process.execPath, [CLI, '-u', 'http://127.0.0.1:9/x', '--scope-typo', '10.20.0.0/16'], {
    encoding: 'utf8',
    timeout: 60000,
    env: { ...process.env, SQLI_NO_FILE_LOG: '1' },
  });
  const out = `${r.stdout || ''}${r.stderr || ''}`;
  assert.notEqual(r.status, 0, `必须拒绝启动，实际退出码 ${r.status}\n输出：${out.slice(0, 400)}`);
  assert.match(out, /无法识别的参数/);
  assert.match(out, /--scope-typo/);
});
