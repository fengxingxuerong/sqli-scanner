// ============================================================================
// vulnEnrich.test.js —— 漏洞条目上下文回填契约测试（交付物「受影响参数」）
// ============================================================================
// 存在理由：报告此前只印内部 pointId hash（sha256 前 8 位），客户无法自解「哪个参数中招」。
// 本测试锁住「受影响参数」的一等字段语义与三条硬约束：
//   ① 自包含——脱离 report.points 也能从 vuln 本身读到 param/location/url/method/vulnType；
//   ② 幂等——重复回填不产生差异，已显式给定的字段不被覆盖；
//   ③ 不写回——纯浅拷贝，输入对象零变更（ReportGenerator 的导出路径依赖此性质）。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  enrichVuln,
  attachVulnContext,
  affectedParamLabel,
  affectedUrlOf,
  affectedMethodOf,
} from '../src/engine/vulnEnrich.js';
import { vulnTypeOf, locationText, VULN_TAXONOMY, VULN_TYPE_FALLBACK } from '../src/services/vulnTaxonomy.js';

const TARGET = { baseUrl: 'http://t.local/api/search?id=1', method: 'POST' };
const POINT = { id: 'p1', location: 'url', param: 'id', originalValue: '1' };

test('vulnTypeOf: 九条技术通道全部映射到规范类型 + CWE（无遗漏）', () => {
  const techniques = ['union', 'error', 'boolean', 'time', 'stacked', 'oob', 'second_order', 'inline', 'nosql'];
  for (const t of techniques) {
    const vt = vulnTypeOf(t);
    assert.equal(vt.key, t, `${t} 应命中词表而非兜底`);
    assert.match(vt.cwe, /^CWE-\d+$/, `${t} 的 CWE 形如 CWE-89；实得 ${vt.cwe}`);
    assert.ok(vt.nameZh && vt.nameEn, `${t} 缺中英文类型名`);
    assert.equal(vt.owasp, 'A03:2021-Injection');
  }
  // NoSQL 不属于 CWE-89（口径不许把差异塞进同一个编号）
  assert.equal(vulnTypeOf('nosql').cwe, 'CWE-943');
  assert.equal(vulnTypeOf('union').cwe, 'CWE-89');
  assert.equal(Object.keys(VULN_TAXONOMY).length, 9);
});

test('vulnTypeOf: 未收录技术走兜底且不编造子类型（key 回填原 technique）', () => {
  const vt = vulnTypeOf('some_future_channel');
  assert.equal(vt.key, 'some_future_channel');
  assert.equal(vt.cwe, VULN_TYPE_FALLBACK.cwe);
  assert.equal(vt.nameZh, VULN_TYPE_FALLBACK.nameZh);
  // 空输入不得抛错
  assert.equal(vulnTypeOf(undefined).key, 'unknown');
});

test('locationText: 注入位置中文化；未知位置原样返回不编造', () => {
  assert.match(locationText('url'), /URL 查询参数/);
  assert.match(locationText('body'), /请求体/);
  assert.match(locationText('cookie'), /Cookie/);
  assert.match(locationText('header'), /请求头/);
  assert.match(locationText('path'), /路径段/);
  assert.match(locationText('direct'), /直连/);
  assert.equal(locationText('weird_place'), 'weird_place');
  assert.equal(locationText(null), '未知位置');
});

test('enrichVuln: 补齐五要素字段（参数名/位置/受影响请求/漏洞类型）', () => {
  const out = enrichVuln({ pointId: 'p1', technique: 'union', riskLevel: 'High' }, POINT, TARGET);
  assert.equal(out.param, 'id');
  assert.equal(out.location, 'url');
  assert.match(out.locationText, /URL 查询参数/);
  assert.equal(out.url, TARGET.baseUrl);
  assert.equal(out.method, 'POST');
  assert.match(out.affectedParam, /^id · URL 查询参数/);
  assert.equal(out.vulnType.cwe, 'CWE-89');
  // 原字段一个不少
  assert.equal(out.pointId, 'p1');
  assert.equal(out.technique, 'union');
});

test('enrichVuln: 不覆盖调用方已显式给定的字段（幂等不变量）', () => {
  const preset = {
    pointId: 'p1', technique: 'union',
    param: 'explicit_param', location: 'header', locationText: '显式位置',
    url: 'http://explicit/', method: 'PUT', affectedParam: '显式标签',
  };
  const out = enrichVuln(preset, POINT, TARGET);
  assert.equal(out.param, 'explicit_param');
  assert.equal(out.location, 'header');
  assert.equal(out.locationText, '显式位置');
  assert.equal(out.url, 'http://explicit/');
  assert.equal(out.method, 'PUT');
  assert.equal(out.affectedParam, '显式标签');
  // 二次回填结果与首次一致（可重复调用）
  assert.deepEqual(enrichVuln(out, POINT, TARGET), out);
});

test('enrichVuln: 不写回入参对象（导出路径依赖纯函数语义）', () => {
  const vuln = { pointId: 'p1', technique: 'boolean' };
  const out = enrichVuln(vuln, POINT, TARGET);
  assert.notEqual(out, vuln);
  assert.equal('param' in vuln, false);
  assert.equal('vulnType' in vuln, false);
});

test('enrichVuln: point 缺失（历史快照）时仍给漏洞类型，不抛错', () => {
  const out = enrichVuln({ pointId: 'ghost', technique: 'time' }, null, TARGET);
  assert.equal(out.vulnType.cwe, 'CWE-89');
  assert.equal(out.param, undefined); // 无参数名就不编造
  assert.match(out.affectedParam, /未记录参数名/);
  assert.equal(out.url, TARGET.baseUrl); // 受影响请求仍可从 target 得到
  // 非法输入不得抛
  assert.doesNotThrow(() => enrichVuln(null, null, null));
  assert.equal(enrichVuln(undefined, POINT, TARGET), undefined);
});

test('affectedParamLabel: 直连模式退化为 SQL 模板标识，不产出空单元格', () => {
  assert.match(affectedParamLabel('id', 'url', POINT), /^id · /);
  assert.match(affectedParamLabel(null, 'direct', { sqlTemplate: 'SELECT 1' }), /直连 SQL 模板/);
  assert.match(affectedParamLabel(null, 'url', {}), /未记录参数名/);
});

test('affectedUrlOf / affectedMethodOf: 表单 actionUrl 与 formMethod 优先', () => {
  assert.equal(affectedUrlOf({ actionUrl: 'http://t.local/submit' }, TARGET), 'http://t.local/submit');
  assert.equal(affectedUrlOf({}, TARGET), TARGET.baseUrl);
  assert.equal(affectedUrlOf({}, {}), null);
  assert.equal(affectedMethodOf({ formMethod: 'post' }, TARGET), 'POST');
  assert.equal(affectedMethodOf({}, TARGET), 'POST');
  assert.equal(affectedMethodOf({}, {}), 'GET');
});

test('attachVulnContext: 按 pointId 回填整份报告，且不改动入参 report', () => {
  const report = {
    target: TARGET,
    points: [POINT, { id: 'p2', location: 'body', param: 'q' }],
    vulns: [
      { pointId: 'p1', technique: 'union' },
      { pointId: 'p2', technique: 'boolean' },
      { pointId: 'gone', technique: 'error' }, // 找不到 point：降级但不丢条目
    ],
  };
  const out = attachVulnContext(report);
  assert.notEqual(out, report);
  assert.equal(out.vulns.length, 3);
  assert.equal(out.vulns[0].param, 'id');
  assert.equal(out.vulns[1].param, 'q');
  assert.equal(out.vulns[2].vulnType.cwe, 'CWE-89');
  // 入参未被污染
  assert.equal('param' in report.vulns[0], false);
  assert.deepEqual(report.vulns.map((v) => v.pointId), ['p1', 'p2', 'gone']);
});

test('attachVulnContext: 空报告/无漏洞时原样返回（不抛、不新建对象）', () => {
  const empty = { target: TARGET, points: [], vulns: [] };
  assert.equal(attachVulnContext(empty), empty);
  const noVulns = { target: TARGET, points: [POINT] };
  assert.equal(attachVulnContext(noVulns), noVulns);
  assert.equal(attachVulnContext(null), null);
});
