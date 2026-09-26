// ============================================================================
// terminalSafe.test.js —— 终端 / 日志出口的控制序列消毒
// ============================================================================
// 报告三件套（HTML / markdown / CSV）的出口消毒已各修过一次，但**终端与日志**这两个
// 出口此前没人管 —— 而拖库结果与 os-shell 回显是整条链上目标可控度最高的字节流
// （os-shell 打印的就是"在目标上执行命令的输出"）。可达后果不是"输出难看"：
//   OSC 0 -> 改写操作员终端标题；
//   OSC 8 -> 终端里的可点击超链接，显示文字与真实目标可以完全不同；
//   CSI   -> 光标移动 / 擦行，可改写刚刚打印的那条结果；
//   CR    -> 回车覆盖当前行；裸换行 -> 伪造一条时间戳与 level 都齐全的假日志行。
// 判据含"接线"：只测纯函数等于没测（本仓踩过"只测被调函数、测试全绿而入口坏"）。
// 本文件内所有控制字符都用 String.fromCharCode 构造，不出现裸控制字节。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { sanitizeForTerminal } from '../src/core/terminalSafe.js';
import { redact } from '../src/core/logger.js';
import { printExtractView } from '../bin/cli.js';

const ESC = String.fromCharCode(27);
const BEL = String.fromCharCode(7);
const CR = String.fromCharCode(13);
const NUL = String.fromCharCode(0);
const DEL = String.fromCharCode(127);
const NEL = String.fromCharCode(133);
const KEEP = new Set([String.fromCharCode(10), String.fromCharCode(9)]);
const hasControl = (s) => [...s].some((c) => {
  const n = c.codePointAt(0);
  return !KEEP.has(c) && ((n < 32) || n === 127 || (n >= 128 && n <= 159));
});

const HOSTILE = [
  [ESC + ']0;PWNED' + BEL, 'OSC 0 改终端标题'],
  [ESC + ']8;;http://evil.example' + BEL + '点开我' + ESC + ']8;;' + BEL, 'OSC 8 终端超链接'],
  [ESC + '[2K' + ESC + '[1;1H已备份完成', 'CSI 擦行 + 光标归位'],
  ['a' + ESC + '[38;5;196m红', 'CSI 改色（伪装成引擎自己的高亮）'],
  ['admin' + CR + '伪造一行', 'CR 覆盖当前行'],
  ['x' + String.fromCharCode(10) + '[2030-01-01 00:00:00] [info] 这条日志没发生过', '换行伪造日志行'],
  ['nul' + NUL + 'del' + DEL + 'c1' + NEL, 'NUL / DEL / C1'],
];

test('纯函数：控制序列转成可见标记，换行与制表符保留', () => {
  for (const [raw, why] of HOSTILE) {
    const got = sanitizeForTerminal(raw);
    assert.equal(hasControl(got), false, why + ' 未被消毒: ' + JSON.stringify(got));
    assert.match(got, /<U\+001B>|<U\+000D>|<U\+0000>|<U\+007F>|<U\+0085>|这条日志没发生过/);
  }
  const layout = sanitizeForTerminal('a' + String.fromCharCode(10) + '	b');
  assert.equal(layout, 'a' + String.fromCharCode(10) + '	b', '换行/制表符承载排版，不该被吃掉');
  assert.equal(sanitizeForTerminal('users'), 'users', '普通文本必须逐字节不变（含中文：口令）');
  assert.equal(sanitizeForTerminal(null), '', 'null/undefined 归空串');
});

test('纯函数幂等：套两次不会变成双重转义（多出口都调它是常态）', () => {
  for (const [raw] of HOSTILE) {
    const once = sanitizeForTerminal(raw);
    assert.equal(sanitizeForTerminal(once), once);
  }
});

test('接线（日志）：logger 的最终格式化点会消毒，且 redact 仍在那条路上', () => {
  assert.equal(hasControl(redact('前' + ESC + ']0;PWNED' + BEL + '后')), false);
  assert.equal(redact('Cookie=abc123'), redact('Cookie=abc123'));
  const src = readFileSync(new URL('../src/core/logger.js', import.meta.url), 'utf8');
  assert.match(src, /format\.printf\(\(\{[^}]*\}\) =>[\s\S]{0,220}redact\(message/, 'printf 不再过 redact()，本支守卫会假绿');
});

test('接线（CLI）：拖库视图的输出字节流里没有控制字符', () => {
  const report = {
    data: {
      databases: ['sqli' + String.fromCharCode(10) + 'fake'],
      tables: { ['db' + ESC]: ['users' + BEL] },
      columns: { ['db' + ESC + '.users' + BEL]: ['pwd' + CR] },
      rows: { ['db' + ESC + '.users' + BEL]: [{ ['pwd' + CR]: 'v' + ESC + '[2Kx' }] },
      currentDb: 'a' + ESC + ']0;t' + BEL,
      currentUser: 'b' + String.fromCharCode(8),
      passwords: 'c' + DEL,
    },
  };
  const chunks = [];
  const orig = process.stdout.write;
  process.stdout.write = (c, ...rest) => { chunks.push(typeof c === 'string' ? c : String(c)); return true; };
  try { printExtractView(report); } finally { process.stdout.write = orig; }
  const outStr = chunks.join('');
  assert.ok(outStr.length > 20, '视图什么都没打印，本断言就是空的');
  assert.equal(hasControl(outStr), false, '输出里仍有活的控制序列: ' + JSON.stringify(outStr.slice(0, 200)));
  assert.match(outStr, /<U\+001B>/, '应看到转义标记，证明目标可控数据真的经过了这里');
});
