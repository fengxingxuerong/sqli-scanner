import { test } from 'node:test';
import assert from 'node:assert/strict';
import { tamperRegistry } from '../src/core/tamper/TamperRegistry.js';
// 导入即触发内置插件注册（applyTampers.js 内部 registerMany）
import '../src/core/tamper/applyTampers.js';

// 内置 tamper 全量清单（v2 既有 7 + v3 新增 9 + v7 新增 12 = 28）
const ALL_NAMES = [
  'space2comment', 'randomcase', 'charencode', 'equaltolike', 'keywordSplit',
  'comments', 'base64encode', 'space2plus', 'space2dash', 'multiplespaces',
  'versionedkeywords', 'charunicodeencode', 'nonrecursivereplace', 'lowercase',
  'uppercase', 'percentage',
  // v7 新增高频 WAF 绕过子集
  'between', 'greatest', 'least', 'ifnull2ifisnull', 'versionedmorekeywords',
  'halfversionedmorekeywords', 'modsecurityversioned', 'modsecurityzeroversioned',
  'chardoubleencode', 'unmagicquotes', 'appendnullbyte', 'randomwhitespace',
  // v9 新增 34 个（内置总数 28 → 62）
  'apostrophemask', 'apostrophenullencode', 'apostrophe2char', 'bluecoat',
  'commentbeforewhitespace', 'commentafterwhitespace', 'concat2concatws',
  'commalesslimit', 'commalessmid', 'escapequotes', 'htmlencode',
  'ifnull2casewhenisnull', 'informationschemacomment', 'overlongutf8', 'quote2hex',
  'randomcomments', 'securesphere', 'sp_password', 'space2hash', 'space2morecomment',
  'space2mssqlblank', 'space2mssqlhash', 'space2mysqlblank', 'space2mysqldash',
  'space2randomblank', 'space2nbsp', 'space2blank', 'symboliclogical',
  'unionalltounion', 'misunion', 'sleep2delay', 'sleep2pg', 'tab2comment', 'zeroversioned',
];

test('全部内置 tamper 已注册', () => {
  for (const n of ALL_NAMES) assert.ok(tamperRegistry.get(n), `未注册: ${n}`);
});

test('space2plus 空格转 +', () => {
  assert.equal(tamperRegistry.get('space2plus').transform('a AND b'), 'a+AND+b');
});

test('space2dash 空格转 --hex', () => {
  const out = tamperRegistry.get('space2dash').transform('a b');
  assert.match(out, /^a--[0-9a-f]+b$/);
});

test('multiplespaces 关键字后追加空格', () => {
  assert.equal(tamperRegistry.get('multiplespaces').transform('SELECT x'), 'SELECT  x');
});

test('versionedkeywords 用 /*! ... */ 包裹关键字', () => {
  assert.equal(tamperRegistry.get('versionedkeywords').transform('SELECT x'), '/*! SELECT */ x');
});

test('charunicodeencode 字母编码为 %uXXXX', () => {
  assert.equal(tamperRegistry.get('charunicodeencode').transform('ab'), '%u0061%u0062');
});

test('nonrecursivereplace 双写关键字', () => {
  assert.equal(tamperRegistry.get('nonrecursivereplace').transform('OR'), 'OROR');
});

test('lowercase 全小写', () => {
  assert.equal(tamperRegistry.get('lowercase').transform('SeLeCt'), 'select');
});

test('uppercase 全大写', () => {
  assert.equal(tamperRegistry.get('uppercase').transform('SeLeCt'), 'SELECT');
});

test('percentage MSSQL 关键字间插 %', () => {
  assert.equal(tamperRegistry.get('percentage').transform('OR'), 'O%R');
});

test('链式调用：space2comment + lowercase 顺序生效', () => {
  const out = tamperRegistry.resolve(['space2comment', 'lowercase'])
    .reduce((acc, p) => p.transform(acc, {}), 'SELECT 1');
  assert.equal(out, 'select/**/1');
});

// v5：模拟 WAF 关键词拦截，验证 tamper 绕过率（真实工具竞争力：过 WAF 是扫描器刚需）
function wafBlocks(sql) {
  // 简单 WAF：拦截"关键字+空格"分隔形式（模拟未做深层语法解析的防护）
  return /union\s+select/i.test(sql) || /and\s+1=1/i.test(sql);
}

test('tamper 绕过 WAF：全部 16 个 tamper 已注册可解析', () => {
  for (const n of ALL_NAMES) {
    assert.ok(tamperRegistry.resolve([n]).length === 1, `无法解析: ${n}`);
  }
});

test('tamper 绕过 WAF：space2comment 将空格转注释，绕过关键词拦截', () => {
  const raw = 'UNION SELECT flag FROM secrets';
  assert.equal(wafBlocks(raw), true);
  const out = tamperRegistry.resolve(['space2comment'])
    .reduce((acc, p) => p.transform(acc, {}), raw);
  assert.equal(wafBlocks(out), false); // 空格消失 → 不再命中 union select 规则
});

test('tamper 绕过 WAF：组合 tamper 对多类 payload 绕过率 100%', () => {
  const payloads = ['UNION SELECT flag FROM secrets', '1 AND 1=1', 'normal search'];
  assert.equal(payloads.filter(wafBlocks).length, 2); // 原始前两个被拦
  const after = payloads.map((s) =>
    tamperRegistry.resolve(['space2comment', 'lowercase'])
      .reduce((acc, p) => p.transform(acc, {}), s)
  );
  assert.equal(after.filter(wafBlocks).length, 0); // 全部绕过
});

// v7 新插件单测（确定逻辑，可测优先）
test('between: > 转 NOT BETWEEN 0 AND、< 转 BETWEEN 0 AND', () => {
  assert.equal(tamperRegistry.get('between').transform('a>1 AND b<2'),
    'a NOT BETWEEN 0 AND 1 AND b BETWEEN 0 AND 2');
});
test('greatest: a>b 转 GREATEST(a,b)=a', () => {
  assert.equal(tamperRegistry.get('greatest').transform('a>1'), 'GREATEST(a,1)=a');
});
test('least: a<b 转 LEAST(a,b)=a', () => {
  assert.equal(tamperRegistry.get('least').transform('a<1'), 'LEAST(a,1)=a');
});
test('ifnull2ifisnull: IFNULL(a,b) 改写', () => {
  assert.equal(tamperRegistry.get('ifnull2ifisnull').transform('IFNULL(a,b)'), 'IF(ISNULL(a),b,a)');
});
test('versionedmorekeywords: 包裹每个关键字', () => {
  assert.equal(tamperRegistry.get('versionedmorekeywords').transform('UNION SELECT a'),
    '/*! UNION */ /*! SELECT */ a');
});
test('halfversionedmorekeywords: 带版本号包裹', () => {
  assert.equal(tamperRegistry.get('halfversionedmorekeywords').transform('SELECT x'), '/*!50540 SELECT*/ x');
});
test('modsecurityversioned: 包裹核心关键字', () => {
  assert.equal(tamperRegistry.get('modsecurityversioned').transform('1 AND 1=1'), '1 /*! AND */ 1=1');
});
test('modsecurityzeroversioned: 零版本包裹', () => {
  assert.equal(tamperRegistry.get('modsecurityzeroversioned').transform('1 AND 1=1'), '1 /*!00000 AND */ 1=1');
});
test('chardoubleencode: 双重编码空格', () => {
  assert.equal(tamperRegistry.get('chardoubleencode').transform(' '), '%2520');
});
test('unmagicquotes: 宽字节绕过', () => {
  assert.equal(tamperRegistry.get('unmagicquotes').transform("a'b"), "a%bf%27b");
});
test('appendnullbyte: 末尾追加 %00', () => {
  assert.equal(tamperRegistry.get('appendnullbyte').transform('a'), 'a%00');
});
test('randomwhitespace: 空格轮换空白字符', () => {
  assert.equal(tamperRegistry.get('randomwhitespace').transform('a b c'), 'a%09b%0ac');
});

// v7 绕过率扩展：新插件对专用 WAF 规则的绕过
function wafBlocksCmp(sql) {
  return />|</.test(sql); // 拦截比较符号
}
test('tamper 绕过 WAF：between 将比较符变形绕过', () => {
  const raw = '1 AND a>1';
  assert.equal(wafBlocksCmp(raw), true);
  const out = tamperRegistry.resolve(['between']).reduce((acc, p) => p.transform(acc, {}), raw);
  assert.equal(wafBlocksCmp(out), false);
});
test('tamper 绕过 WAF：versionedmorekeywords 注释包裹绕过关键字规则', () => {
  const raw = 'UNION SELECT flag FROM secrets';
  assert.equal(wafBlocks(raw), true);
  const out = tamperRegistry.resolve(['versionedmorekeywords'])
    .reduce((acc, p) => p.transform(acc, {}), raw);
  assert.equal(wafBlocks(out), false);
});

// v9 新插件确定性单测
test('commalesslimit: LIMIT a, b 转 LIMIT b OFFSET a', () => {
  assert.equal(tamperRegistry.get('commalesslimit').transform('LIMIT 0, 1'), 'LIMIT 1 OFFSET 0');
});
test('commalessmid: MID(a, b, c) 转 MID(a FROM b FOR c)', () => {
  assert.equal(tamperRegistry.get('commalessmid').transform('MID(password,1,3)'), 'MID(password FROM 1 FOR 3)');
});
test('symboliclogical: AND→&& OR→||', () => {
  assert.equal(tamperRegistry.get('symboliclogical').transform('1 AND 2 OR 3'), '1 && 2 || 3');
});
test('quote2hex: 字符串字面量转 0x 十六进制', () => {
  assert.equal(tamperRegistry.get('quote2hex').transform("'abc'"), '0x616263');
});
test('unionalltounion: UNION ALL → UNION', () => {
  assert.equal(tamperRegistry.get('unionalltounion').transform('UNION ALL SELECT 1'), 'UNION SELECT 1');
});
test('misunion: UNION → UNI/**/ON', () => {
  assert.equal(tamperRegistry.get('misunion').transform('UNION SELECT 1'), 'UNI/**/ON SELECT 1');
});
test('space2nbsp: 空格 → %a0', () => {
  assert.equal(tamperRegistry.get('space2nbsp').transform('a b'), 'a%a0b');
});
test('space2blank: 空格 → %0b', () => {
  assert.equal(tamperRegistry.get('space2blank').transform('a b'), 'a%0bb');
});
test('ifnull2casewhenisnull: IFNULL → CASE WHEN', () => {
  assert.equal(tamperRegistry.get('ifnull2casewhenisnull').transform('IFNULL(a,b)'),
    'CASE WHEN ISNULL(a) THEN b ELSE a END');
});
test('apostrophe2char: 单引号 → CHAR(39)', () => {
  assert.equal(tamperRegistry.get('apostrophe2char').transform("a'b"), 'aCHAR(39)b');
});
test('zeroversioned: 关键字零版本注释包裹', () => {
  assert.equal(tamperRegistry.get('zeroversioned').transform('SELECT 1'), '/*!00000SELECT*/ 1');
});

// v9 绕过率：新插件对专用 WAF 规则的绕过
function wafBlocksLogical(sql) {
  return /\bAND\b|\bOR\b/.test(sql); // 拦截逻辑关键字
}
test('tamper 绕过 WAF：symboliclogical 将逻辑关键字变形绕过', () => {
  const raw = '1 AND 1=1';
  assert.equal(wafBlocksLogical(raw), true);
  const out = tamperRegistry.resolve(['symboliclogical']).reduce((acc, p) => p.transform(acc, {}), raw);
  assert.equal(wafBlocksLogical(out), false);
});

// v9 全量注册校验：62 个插件全部已注册且可解析（v10 扩至 64）
test('v9：全部 64 个 tamper 均已注册且可解析', () => {
  assert.equal(tamperRegistry.list().length, 64);
  for (const n of ALL_NAMES) {
    assert.equal(tamperRegistry.resolve([n]).length, 1, `无法解析: ${n}`);
  }
});
