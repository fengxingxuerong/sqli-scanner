// ============================================================================
// server/tests/echoStrip.jsonEcho.test.js —— 回显剔除的「JSON 转义型回显」契约（D112）
//
// 出处（外部裁判 3 号 DVGA 抓到的真误报，不是设想）：
//   POST /graphql  body={"query":"{ search(keyword: \"x\") { __typename } }"}
//   ↑ 这个点走官方 `resolve_search` 的 ORM `like(search)` 参数化，**手工证实不可注入**
//     （`x'` / `x' OR 1=1-- -` / `x' UNION SELECT 1-- -` 全部 200 `{"data":{"search":[]}}`）。
//   但引擎报了 High / CVSS 8.2 的「报错注入」——payload 是
//     `{ search(keyword: "x") { __typename } }' AND extractvalue(1,concat(0x7e,(SELECT version())))-- -`
//   即把 payload **追加在整个 GraphQL 查询串之后**（整串替换 + 后缀），GraphQL 解析失败，
//   服务端把这段原文塞进 `{"errors":[{"message":"Syntax Error … \"x\" … extractvalue …"}]}`。
//   响应里的 payload 是 **JSON 转义形态**（`"` → `\"`、换行 → `\n`），旧变体集合剔不掉
//   ⇒ payload 自带的 `extractvalue` 命中 ERROR_SIG（签名里含 payload 关键字）⇒ 假阳性。
//
// 本文件钉死的能力：JSON 字符串转义形态的回显必须被剔干净。
// ⚠️ 纪律（同 echoStrip.escapeVariant.test.js）：断言必须敏感 —— §B 用「无 JSON 变体」的
//    弱版跑同一输入，证明剔不干净时断言真的会红。
// ============================================================================

import test from 'node:test';
import assert from 'node:assert/strict';
import { stripEchoedPayload, normalizeEcho } from '../src/engine/echoStrip.js';
import { ERROR_SIG } from '../src/engine/payloads.js';

/** D112 修复前的变体集合（无 JSON 转义），仅用于证明 §A 敏感 */
function weakStripNoJson(body, payload) {
  let t = normalizeEcho(body);
  const variants = new Set([String(payload), normalizeEcho(payload)]);
  for (const v of [...variants]) {
    if (!v) continue;
    variants.add(v.replace(/'/g, "''"));
    variants.add(v.replace(/'/g, "\\'"));
  }
  try {
    variants.add(encodeURIComponent(payload));
  } catch { /* noop */ }
  for (const v of variants) {
    if (v && v.length > 3) t = t.split(v).join('');
  }
  return t;
}

// 真实样本：DVGA /graphql 对注入请求的响应（逐字符取自实测，未美化）
const QUERY = '{ search(keyword: "x") { __typename } }';
const PAYLOAD = `${QUERY}' AND extractvalue(1,concat(0x7e,(SELECT version())))-- -`;
const DVGA_BODY =
  '{"errors":[{"message":"Syntax Error GraphQL (1:40) Unexpected character \\"\'\\".\\n\\n1: ' +
  '{ search(keyword: \\"x\\") { __typename } }\' AND extractvalue(1,concat(0x7e,(SELECT version())))-- -\\n' +
  '                                          ^\\n","locations":[{"line":1,"column":40}]}]}';

test('§A JSON 转义型回显（DVGA GraphQL 真实样本）必须剔干净', () => {
  const out = stripEchoedPayload(DVGA_BODY, PAYLOAD);
  assert.ok(!out.includes('extractvalue'), `JSON 转义回显未被剔干净：${out}`);
  assert.ok(!out.includes('__typename'), `payload 原文残留：${out}`);
  // 剔除后不得再命中 ERROR_SIG —— 这才是对「误报」本身的断言，不只是字符串层面
  assert.equal(out.match(ERROR_SIG), null, `剔除后仍命中 ERROR_SIG：${out.match(ERROR_SIG)?.[0]}`);
});

test('§A2 双层 JSON 转义（错误消息套娃 / 二次序列化）也必须剔干净', () => {
  const inner = JSON.stringify(PAYLOAD).slice(1, -1);
  const double = JSON.stringify(`{"errors":[{"message":"${inner}"}]}`);
  const out = stripEchoedPayload(double, PAYLOAD);
  assert.ok(!out.includes('extractvalue'), `双层 JSON 转义回显未被剔干净：${out}`);
});

test('§B 断言敏感性：无 JSON 变体的弱版在同一输入上必须仍然命中 ERROR_SIG', () => {
  const weakOut = weakStripNoJson(DVGA_BODY, PAYLOAD);
  const m = weakOut.match(ERROR_SIG);
  assert.ok(m, '弱版竟也剔干净了 —— §A 对「有没有 JSON 变体」不敏感，是假绿');
  assert.equal(m[0], 'extractvalue');
});

test('§C 反向：JSON API 里的**真** SQL 报错不得被误删（防替出假阴性）', () => {
  // DVGA 真值点 pastes(filter) 的实测报错（payload 是 `x'`，报错来自 sqlite 而非回显）
  const realErr =
    '{"errors":[{"message":"(sqlite3.OperationalError) near \\"x\'\'\\": syntax error\\n' +
    '[SQL: SELECT pastes.id AS pastes_id, pastes.title AS pastes_title FROM pastes WHERE ...]"}]}';
  const out = stripEchoedPayload(realErr, 'x\'');
  assert.ok(out.includes('sqlite3.OperationalError'), `真报错被误删：${out}`);
  assert.ok(out.match(ERROR_SIG), `真报错不再命中 ERROR_SIG：${out}`);
});
