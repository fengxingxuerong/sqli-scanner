// ============================================================================
// server/tests/echoStrip.variantsMatrix.test.js —— 回显变体**矩阵**契约（D112 续）
//
// 背景：本仓的回显剔除已经「抓到一个补一个」补了四轮（SQL 转义 → 反斜杠 → URL 编码
// → JSON 转义），每轮只把**当时那一种**形态钉进测试，其余形态继续漏 —— 直到 DVGA
// 外部裁判用 JSON 转义形态再抓一次（2026-10-20）。这是典型的「补一个漏一片」。
//
// 本文件把它反过来：**先列形态矩阵，再要求变体生成器覆盖全部形态**。
// 新增形变必须同时加进 `FORMS` 与 `echoVariants`，否则 §A 会红（矩阵逼你把口子堵全）。
//
// ⚠️ 纪律（同 echoStrip.escapeVariant.test.js / echoStrip.jsonEcho.test.js）：
//    断言必须敏感 —— §B 用「只有原文」的弱版跑同一批输入，证明剔不干净时真的会红。
// ============================================================================

import test from 'node:test';
import assert from 'node:assert/strict';
import { stripEchoedPayload, echoVariants, stripLongestPrefix, normalizeEcho, ECHO_TRUNC_MIN } from '../src/engine/echoStrip.js';
import { ERROR_SIG } from '../src/engine/payloads.js';

// 用**含双引号**的 payload：这条正是 DVGA/GraphQL 场景的真实形状（查询串里有 `"`）。
// 关键原因：payload 若不含 `"`/控制字符，JSON 转义形态会退化成原文 ⇒ 矩阵里两条形态
// 变成同一条，数量断言会假红（掩盖真正该红的「形态没进生成器」）。
const PAYLOAD = '{ pastes(filter: "x") { id } }\' AND extractvalue(1,concat(0x7e,version()))-- -';

/**
 * 形态矩阵：[name, 形变函数, probe]
 * `probe` = 剔除后**不该残留**的字符串 —— 多数形态是 payload 自带的明文关键字；
 * base64 这类「编码后无明文」的形态必须用**它自己的编码串**当 probe，
 * 否则断言恒真（响应里压根没有 extractvalue 明文）⇒ 摘掉实现也不红 = 假绿
 * （本文件首版就犯了这个：base64 与截断两条用例空转，缺陷注入时它们没红）。
 */
const FORMS = [
  ['原文', (p) => p, 'extractvalue'],
  ['SQL 转义（单引号翻倍）', (p) => p.replace(/'/g, "''"), 'extractvalue'],
  ['反斜杠转义', (p) => p.replace(/'/g, "\\'"), 'extractvalue'],
  ['URL 编码', (p) => encodeURIComponent(p), 'extractvalue'],
  ['双重 URL 编码', (p) => encodeURIComponent(encodeURIComponent(p)), 'extractvalue'],
  ['JSON 转义', (p) => JSON.stringify(p).slice(1, -1), 'extractvalue'],
  ['JSON 双层转义', (p) => JSON.stringify(JSON.stringify(p).slice(1, -1)).slice(1, -1), 'extractvalue'],
  ['Unicode \\uXXXX', (p) => p.replace(/['"\\]/g, (c) => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0')), 'extractvalue'],
  // base64：probe 取编码串本身（ERROR_SIG 本就不匹配 base64，用关键字断言是空转）
  ['base64', (p) => Buffer.from(p, 'utf8').toString('base64'), Buffer.from(PAYLOAD, 'utf8').toString('base64')],
];

/** 弱版：只剔原文（修复前的共同形状），用于 §B 证明矩阵敏感 */
function weakStrip(body, payload) {
  return normalizeEcho(body).split(String(payload)).join('');
}

// §A 矩阵：每一条形变都必须被剔干净（probe 不得残留），明文形态还不得再命中 ERROR_SIG
for (const [name, form, probe] of FORMS) {
  test(`§A 回显形态「${name}」必须剔干净`, () => {
    const echoed = form(PAYLOAD);
    const body = `<div class="error">near "${echoed}" at line 1</div>`;
    const out = stripEchoedPayload(body, PAYLOAD);
    assert.ok(!out.includes(probe), `形态「${name}」未剔干净：${out}`);
    if (probe === 'extractvalue') {
      assert.equal(out.match(ERROR_SIG), null, `形态「${name}」剔除后仍命中 ERROR_SIG：${out.match(ERROR_SIG)?.[0]}`);
    }
  });
}

// §A2 结构不变量：变体生成器必须**覆盖矩阵里的每一条形变**
// （新增形变而忘了进生成器 ⇒ 这里红，逼你两头都改）
test('§A2 变体生成器覆盖矩阵全部形态（防「补一个漏一片」）', () => {
  const vs = echoVariants(PAYLOAD);
  const distinctForms = new Set(FORMS.map(([, form]) => form(PAYLOAD)));
  for (const [name, form] of FORMS) {
    const echoed = form(PAYLOAD);
    assert.ok(vs.includes(echoed), `变体集合缺形态「${name}」：${echoed.slice(0, 60)}`);
  }
  assert.ok(
    vs.length >= distinctForms.size,
    `变体数 ${vs.length} 少于去重形态数 ${distinctForms.size}（形态没进生成器）`
  );
});

// §B 断言敏感性：弱版（只剔原文）在**关键字仍以明文出现**的形态上必须全部漏
// （base64 / 双重 URL 编码这类形态本身不含明文关键字，弱版自然不命中 —— 把它们算进
//  分母会让断言失真，故按「回显里是否还有明文 extractvalue」筛出可比形态）
// 可比形态 = 弱版（只剔原文）**本来就拿它没办法**的形态。
// 排除两类：① 原文形态（弱版直接剔掉）；② URL/双重 URL（normalizeEcho 会解码回原文）。
const comparableForms = FORMS.filter(([, form]) => normalizeEcho(form(PAYLOAD)) !== PAYLOAD);

test('§B 断言敏感性：弱版在可比形态上必须全部残留 probe（否则 §A 是空转）', () => {
  assert.ok(comparableForms.length >= 5, `可比形态仅 ${comparableForms.length} 条，样本不足`);
  let leaked = 0;
  for (const [, form, probe] of comparableForms) {
    const body = `<div class="error">near "${form(PAYLOAD)}" at line 1</div>`;
    if (weakStrip(body, PAYLOAD).includes(probe)) leaked += 1;
  }
  assert.equal(leaked, comparableForms.length, `弱版只漏 ${leaked}/${comparableForms.length} 条 —— §A 形同空转`);
});

test('§B2 明文形态上，弱版必须仍然命中 ERROR_SIG（对假阳性本身的断言）', () => {
  const plainForms = comparableForms.filter(([, , probe]) => probe === 'extractvalue');
  assert.ok(plainForms.length >= 4, `明文形态仅 ${plainForms.length} 条`);
  let hit = 0;
  for (const [, form] of plainForms) {
    const body = `<div class="error">near "${form(PAYLOAD)}" at line 1</div>`;
    if (weakStrip(body, PAYLOAD).match(ERROR_SIG)) hit += 1;
  }
  assert.equal(hit, plainForms.length, `弱版只命中 ${hit}/${plainForms.length} 条 —— ERROR_SIG 断言不敏感`);
});

// §C 截断型回显：整串被截短，只有前缀在
// ⚠ 截断长度必须**覆盖到关键字明文**（本例 40 字符），否则残留里没有 extractvalue，
// 断言天然成立 ⇒ 摘掉前缀剔除也不红（首版就栽在这：截 24 字符时用例是空转的）
test('§C 截断回显（只回显前缀）按最长前缀剔除', () => {
  const truncated = PAYLOAD.slice(0, 52); // 目标截到 52 字符（须覆盖 extractvalue 全字）
  assert.ok(truncated.includes('extractvalue'), '样本构造错误：截断长度未覆盖关键字');
  const body = `Syntax Error near "${truncated}"`;
  const out = stripEchoedPayload(body, PAYLOAD);
  assert.ok(!out.includes('extractvalue'), `截断回显未剔干净：${out}`);
  assert.equal(out.match(ERROR_SIG), null, `截断回显剔除后仍命中 ERROR_SIG：${out.match(ERROR_SIG)?.[0]}`);
});

test('§C2 短于阈值的前缀不剔（防误删真实报错文本）', () => {
  const shortPrefix = PAYLOAD.slice(0, ECHO_TRUNC_MIN - 1); // 15 字符
  const body = `error near "${shortPrefix}"`;
  const out = stripEchoedPayload(body, PAYLOAD);
  assert.ok(out.includes(shortPrefix), `短前缀被误剔：${out}`);
  // 直接对 stripLongestPrefix 钉阈值语义
  assert.equal(stripLongestPrefix(`x${shortPrefix}y`, PAYLOAD), `x${shortPrefix}y`);
});

// §D 反向：真报错文本不得被误删（防替出假阴性）
test('§D 真报错文本不得被剔除', () => {
  const realErr = '<b>error</b> You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version';
  const out = stripEchoedPayload(realErr, PAYLOAD);
  assert.ok(out.includes('You have an error in your SQL syntax'), `真实报错被误删：${out}`);
  assert.ok(out.match(ERROR_SIG), `真实报错不再命中 ERROR_SIG：${out}`);
});

// §E 边界：空值不崩、空 payload 返回归一化原文
test('§E 空值/空 payload 不崩且返回字符串', () => {
  assert.equal(stripEchoedPayload('', PAYLOAD), '');
  const out = stripEchoedPayload('<p>x</p>', '');
  assert.equal(typeof out, 'string');
  assert.ok(out.includes('x'));
  assert.deepEqual(echoVariants(''), []);
});
