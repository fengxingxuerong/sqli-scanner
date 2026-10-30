// [D211] 报错归因：区分「payload 引起的报错」与「引号引起的报错」
// ============================================================================
// 缺陷（真机实测 demo.testfire.net 的 btnSubmit）：
//   原判据 = 响应含 SQL 错误签名 且 与基线不同 且 二次确认同样报错。
//   但**让 SQL 语法出错只需要一个未闭合的引号** —— 这与「注入是否成立」无关。
//   真实站点（老 Java/PHP 常见）对「含特殊字符的输入」常统一返回带 SQL 片段或驱动
//   报错文案的错误页（且如 Derby/JSP 那样是 HTTP 200，见 D207）⇒ 任何带引号的
//   payload 都假阳。手工 curl 复核：btnSubmit 注入后返回 8360 字节**正常页**、零语法错误。
//
// 修法：命中后补发 **无害引号变体**（保留引号 + 注释后缀，去掉注入载荷），
//   两者引发**同一条**报错签名 ⇒ 归因于引号而非 payload ⇒ 不算命中。
//
// 本组用例钉三件事（缺一不可，前两条是"不许误杀/不许漏"，第三条防"过度收紧"）：
//   ① 引号敏感的安全点 ⇒ 0 命中（消假阳）；
//   ② 真正触发报错函数回显的漏洞点 ⇒ 仍命中（不误杀）；
//   ③ 对照也报错但**签名不同** ⇒ 仍命中（证明不是「对照一报错就一律拒绝」）。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ErrorDetector, buildHarmlessQuoteVariant } from '../src/engine/detectors/ErrorDetector.js';

const TPL = "{ORIG}' AND extractvalue(1,concat(0x7e,(SELECT version())))-- -";

/**
 * 驱动 _probeTemplates 本体（不跑完整 detect）：真实判据 + 打桩请求层。
 * @param {(payload:string)=>string} respond 按请求 payload 返回响应正文
 * @param {string[]} [templates]
 */
async function probe(respond, templates = [TPL]) {
  const d = new ErrorDetector();
  const calls = [];
  d.buildRequest = (_target, _point, payload) => ({ payload });
  d.send = async (_client, _ctx, req) => {
    calls.push(req.payload);
    return { data: respond(req.payload), status: 200 };
  };
  const ctx = {
    httpClient: {},
    target: {},
    point: { id: 'p@body', originalValue: '1' },
    config: {},
  };
  const hit = await d._probeTemplates(ctx, templates, null);
  return { hit, calls };
}

// ——————————————————————————— ① 纯函数：无害引号变体 ———————————————————————————

test('[D211] 无害变体 = 引号前缀 + 注释后缀（-- -）', () => {
  const filled = "1' AND extractvalue(1,concat(0x7e,(SELECT version())))-- -";
  assert.equal(buildHarmlessQuoteVariant(filled, '1'), "1'-- -");
});

test('[D211] 注释后缀 # 与 /**/ 同样保留', () => {
  assert.equal(buildHarmlessQuoteVariant("1' AND extractvalue(1,1)#", '1'), "1'#");
  assert.equal(buildHarmlessQuoteVariant("1' AND extractvalue(1,1)/**/", '1'), "1'/**/");
});

test('[D211] 括号闭合前缀（\')）一并保留，否则对照形态失真', () => {
  assert.equal(buildHarmlessQuoteVariant("1') AND extractvalue(1,1)-- -", '1'), "1')-- -");
});

test('[D211] 双引号闭合模板同样生成对照（否则会绕过归因）', () => {
  // 背景：只认单引号的实现会让 `{ORIG}" AND updatexml(...)` 这类模板跳过对照，
  // 在「引号敏感」目标上继续假阳。
  assert.equal(buildHarmlessQuoteVariant('1" AND updatexml(1,concat(0x7e,(SELECT database())),1)-- -', '1'), '1"-- -');
  assert.equal(buildHarmlessQuoteVariant('1") AND updatexml(1,1)-- -', '1'), '1")-- -');
});

test('[D212] 元组族（INSERT VALUES 的 ,(）同样生成对照', () => {
  // 背景：初版只认引号 ⇒ `{ORIG},(SELECT CAST(…) AS int))-- -` 这类**不含任何引号**
  // 的 payload 会跳过对照，实测把 testfire 的 btnSubmit 误判成报错注入。
  assert.equal(buildHarmlessQuoteVariant('1,(SELECT CAST((SELECT version()) AS int))-- -', '1'), '1,-- -');
  assert.equal(buildHarmlessQuoteVariant('1),(1,(SELECT badfunc_sqli_probe())) )-- -', '1'), '1),-- -');
});

test('[D211] payload 无注入载荷（= 原值 + 注释后缀）⇒ 返回 null', () => {
  assert.equal(buildHarmlessQuoteVariant('1-- -', '1'), null);
  assert.equal(buildHarmlessQuoteVariant('1#', '1'), null);
});

test('[D211] 非字符串 / 空值 ⇒ 返回 null（防御，不抛）', () => {
  assert.equal(buildHarmlessQuoteVariant(''), null);
  assert.equal(buildHarmlessQuoteVariant(null), null);
  assert.equal(buildHarmlessQuoteVariant(undefined), null);
  assert.equal(buildHarmlessQuoteVariant(42), null);
});

// ——————————————————————————— ② 集成：归因口径 ———————————————————————————

test('[D211 ①] 引号敏感的安全点：payload 与无害变体引发同一条报错 ⇒ 不命中', async () => {
  // 真实形态：业务层已参数化（真安全），但遗留校验分支对含引号的输入统一吐 Derby 风格错误页。
  const respond = (p) =>
    p.includes("'") ? '<pre>Syntax error: Encountered "\'" at line 1, column 42.</pre>' : 'PAGE-OK';
  const { hit, calls } = await probe(respond);
  assert.equal(hit, null, '报错可归因于引号本身 ⇒ 不得判为注入');
  // 对照确实发过（否则这条断言只是"没命中"，证明不了归因生效）
  assert.ok(
    calls.includes("1'-- -"),
    `未发出无害引号对照请求，实际请求：${JSON.stringify(calls)}`,
  );
});

test('[D211 ②] 真报错注入点：仅 payload 触发报错函数回显 ⇒ 仍命中（不许误杀）', async () => {
  // 只有含 extractvalue 的请求才报错并回显数据；无害变体返回正常页。
  const respond = (p) => (p.includes('extractvalue') ? "XPATH syntax error: '~5.7.40-log'" : 'PAGE-OK');
  const { hit } = await probe(respond);
  assert.ok(hit, '真正的报错注入点不得被新对照误杀');
  assert.match(hit.match, /XPATH syntax error/);
});

test('[D211 ③] 反向对照：对照也报错但签名不同 ⇒ 仍命中（防「对照一报错就一律拒绝」）', async () => {
  const respond = (p) =>
    p.includes('extractvalue')
      ? "XPATH syntax error: '~5.7.40-log'"
      : 'Syntax error: Encountered "\'" at line 1, column 42.';
  const { hit } = await probe(respond);
  assert.ok(hit, '签名不同说明报错确实由 payload 引起 ⇒ 应当命中');
  assert.match(hit.match, /XPATH syntax error/);
});

test('[D211 ④] 对照不额外增加「未命中点」的请求（只在命中后补发）', async () => {
  let n = 0;
  const respond = () => {
    n += 1;
    return 'PAGE-OK';
  };
  const { hit, calls } = await probe(respond, [TPL, "{ORIG}\" AND updatexml(1,concat(0x7e,(SELECT database())),1)-- -"]);
  assert.equal(hit, null);
  // 2 条模板 × 1 次探测 = 2 个请求；若对照被无条件发出，这里会 ≥ 4
  assert.equal(calls.length, 2, `未命中点的请求数应为 2，实际 ${calls.length}（对照不该无条件发）`);
  assert.equal(n, 2);
});
