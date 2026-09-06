// WAF 厂商向 tamper 插件零覆盖补测：safedog / _360waf 变换行为
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { safedog } from '../src/core/tamper/plugins/safedog.js';
import { _360waf } from '../src/core/tamper/plugins/_360waf.js';

test('safedog：关键字双写（大小写不敏感）+ 引号外空格替换为 tab/newline', () => {
  const out = safedog.transform("SELECT * FROM users WHERE id=1 UNION SELECT 2");
  // 双写：原词不再出现，双写词出现
  assert.ok(!/\bSELECT\b/i.test(out));
  assert.ok(out.includes('SELSELECTECT'));
  assert.ok(!/\bUNION\b/i.test(out));
  assert.ok(out.includes('UNUNIONION'));
  assert.ok(out.includes('WHWHEREERE'));
  assert.ok(out.includes('FRFROMOM'));
  // 引号外不允许残留普通空格（全部被 \t / \n 替换）
  assert.ok(!out.includes(' '));
});

test('safedog：引号内内容原样保留（含空格与关键字字面量）', () => {
  const out = safedog.transform("SELECT 'admin user' FROM t");
  // 引号内 'admin user' 的空格与内容不被改写
  assert.ok(out.includes("'admin user'"));
});

test('_360waf：UNION SELECT 注释分割 + OR/AND 数字内联注释 + CHAR 十六进制化', () => {
  const out = _360waf.transform('1 UNION SELECT CHAR(110) FROM t WHERE 1=1 AND 2=2 OR 3=3');
  assert.ok(out.includes('UNION/**/SELECT'));
  assert.ok(out.includes('CHAR(0x6e)')); // 110 → 0x6e
  assert.ok(out.includes('AND/**/2'));
  assert.ok(out.includes('OR/**/3'));
});

test('_360waf：UNION ALL SELECT 全注释分割 + 小写输入同样命中（关键字归一化大写）', () => {
  assert.ok(_360waf.transform('uNiOn aLl SeLeCt 1').toUpperCase().includes('UNION/**/ALL/**/SELECT'));
  assert.ok(_360waf.transform('union select 1').toUpperCase().includes('UNION/**/SELECT'));
});
