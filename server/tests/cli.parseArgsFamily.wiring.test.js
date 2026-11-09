// ============================================================================
// cli.parseArgsFamily.wiring.test.js —— [D281 2026-11-09] 主链族拆分的接线守卫
// ============================================================================
// D281 把 parseArgs 的百余条 `else if (a === '--x')` 拆进 12 个族函数，主链只剩
// 13 条 `else if (applyXxx(a, args, next))` 空壳。拆分能过 A/B 只证明「这次没改坏」，
// 证明不了「以后不会漏接」：族函数少调一次，对应几十个旗标会静默落进 unknownFlags
// ⇒ 启动被拒/参数失效，而静态的真源扫描（readme-flag-coverage ⑰）仍能看到字面量、
// 一切照绿。本判据直接从源码取旗标字面量，逐条走真实 parseArgs 钉住接线。
//
// 与 configNested.cliDefaults.test.js 的 D21 去重守卫互补：那个防「一个 flag 被两个
// 分支抢」，这个防「一个 flag 一个分支都没有」。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parseArgs } from '../bin/cli/args.js';

// ⚠️ 判据的文本源必须排除整行注释（本仓 D21/D280 两次实测：注释里的示例串会被当真旗标）。
const SRC = readFileSync(new URL('../bin/cli/args.js', import.meta.url), 'utf8')
  .split('\n')
  .filter((l) => !/^\s*\/\//.test(l))
  .join('\n');

/** 族函数里的字面量比较 + OPTIONAL_VALUE_FLAGS 表驱动的两类长旗标 */
function collectLongFlags() {
  const out = new Set();
  for (const m of SRC.matchAll(/a === '(--[A-Za-z0-9-]+)'/g)) out.add(m[1]);
  for (const m of SRC.matchAll(/\['(--[A-Za-z0-9-]+)',\s*'[A-Za-z0-9_]+'\]/g)) out.add(m[1]);
  return [...out].sort();
}

const FLAGS = collectLongFlags();

test('D281 分母守卫：源码旗标提取数不得静默变空（判据恒绿自证）', () => {
  // 215 是 2026-11-09 实测值（188 条字面量 + 表驱动去重）；宽松下限只防「正则失效 → 空集」。
  assert.ok(FLAGS.length > 100, `旗标提取数异常（${FLAGS.length}，预期 >100）⇒ 正则或源码结构变了`);
});

test('D281 接线守卫：每个字面量旗标都必须被主链消费（不能落 unknownFlags）', () => {
  const origErr = console.error;
  const origWarn = console.warn;
  console.error = () => {}; // --no-escape / --union-char 会打印「暂不支持」提示
  console.warn = () => {};
  try {
    const missed = [];
    for (const f of FLAGS) {
      const res = parseArgs([f, 'V']);
      if (res.unknownFlags.includes(f)) missed.push(f);
    }
    assert.deepEqual(missed, [], `这些旗标有字面量却没有接线（族函数漏调？）：${missed.join(', ')}`);
  } finally {
    console.error = origErr;
    console.warn = origWarn;
  }
});

test('D281 反例自证：unknownFlags 收集本身有牙（否则上一条恒绿）', () => {
  assert.deepEqual(
    parseArgs(['--definitely-unknown', 'x']).unknownFlags,
    ['--definitely-unknown'],
    'unknownFlags 不再收集未知旗标 ⇒ 上一条接线守卫会恒绿，必须修'
  );
  // equals 形态（startsWith 分支）与组合向量也走一遍，防族拆分后短链形态被丢
  const eq = parseArgs(['--data-dir=/tmp/x', '--max=5', '--days=3']);
  assert.equal(eq.dataDir, '/tmp/x');
  assert.deepEqual(eq.unknownFlags, []);
  const combo = parseArgs([
    '-u', 'http://t/?id=1', '--level', '3', '--risk', '2', '--tamper', 'space2comment',
    '--scope', '10.0.0.0/8', '--auth', 'u:p', '--cookie', 'a=b', '--technique', 'BEU',
  ]);
  assert.equal(combo.level, 3);
  assert.equal(combo.tamper, 'space2comment');
  assert.deepEqual(combo.unknownFlags, []);
});
