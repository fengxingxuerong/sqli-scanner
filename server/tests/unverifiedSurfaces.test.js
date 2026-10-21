// ============================================================================
// server/tests/unverifiedSurfaces.test.js —— [D123 2026-10-21]
//
// 契约：「哪些注入面没测成」必须逐面摊开、且进结论文案。
// 背景缺口：validity 是整轮级健康度，verdict 只在整轮不可信时转 inconclusive ⇒
// 「目标整体健康、部分注入面被 WAF 吃掉」时报告仍写 no_vulnerability_detected 且不提示。
//
// 本测试钉住的四条判据（每条都对应一个真实误判形态）：
//   ① 被拦未跑完的点 ⇒ 计入 unverified，且按面分组；
//   ② 有意跳过（skipReason）的点 ⇒ **不计入** unverified（否则开 --smart 就刷一屏假信号）；
//   ③ 已命中的点 ⇒ 不计入 unverified（有证据就不叫未验证）；
//   ④ 全测完时 ⇒ 不产出该段（不渲染「0」噪声）。
// ============================================================================
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  summarizeUnverifiedSurfaces,
  unverifiedSentence,
  SURFACE_LABEL,
} from '../src/engine/scan/unverifiedSurfaces.js';

const pt = (id, location, param, extra = {}) => ({ id, location, param, ...extra });

test('D123-①: 被拦未跑完的点计入未验证，并按注入面分组', () => {
  const points = [
    pt('a', 'url', 'id'),
    pt('b', 'header', 'User-Agent'),
    pt('c', 'header', 'X-Forwarded-For'),
    pt('d', 'cookie', 'sid'),
  ];
  const r = summarizeUnverifiedSurfaces({
    points,
    fullyTested: ['a'], // url 面跑完了
    inconclusivePoints: ['b', 'c', 'd'],
  });
  assert.equal(r.totalUnverified, 3, 'b/c/d 三个点都没跑完');
  assert.equal(r.affectedSurfaces, 2, 'header + cookie 两类面');
  const header = r.surfaces.find((x) => x.surface === 'header');
  assert.equal(header.unverified, 2);
  assert.equal(header.points, 2);
  assert.equal(header.tested, 0);
  assert.equal(header.label, SURFACE_LABEL.header);
  assert.deepEqual(header.sampleParams, ['User-Agent', 'X-Forwarded-For'], '样例参数名给出指路信息');
  // url 面全测完 ⇒ 不该出现在结果里（只报有未验证的面）
  assert.equal(r.surfaces.some((x) => x.surface === 'url'), false, '全测完的面不出现');
});

test('D123-②: skipReason 的点不计入未验证（防 --smart 刷假信号）', () => {
  const points = [
    pt('a', 'url', 'id', { skipReason: 'static' }),
    pt('b', 'url', 'q', { skipReason: 'validation-skip' }),
    pt('c', 'header', 'X-Api-Key'),
  ];
  const r = summarizeUnverifiedSurfaces({
    points,
    fullyTested: [], // 被跳过的点本就不会进 fullyTested
    inconclusivePoints: ['c'],
  });
  assert.equal(r.totalUnverified, 1, '只有 c 是真未验证；a/b 是有意跳过');
  assert.equal(r.surfaces.length, 1);
  assert.equal(r.surfaces[0].surface, 'header');
});

test('D123-③: 已命中的点不计入未验证（有证据就不叫未验证）', () => {
  const points = [pt('a', 'url', 'id'), pt('b', 'body', 'uname')];
  const r = summarizeUnverifiedSurfaces({
    points,
    fullyTested: [], // 两个都没进 fullyTested（模拟守卫中止）
    vulns: [{ pointId: 'a', technique: 'boolean' }],
    inconclusivePoints: ['a', 'b'],
  });
  assert.equal(r.totalUnverified, 1, 'a 已命中 ⇒ 只剩 b');
  assert.equal(r.surfaces[0].surface, 'body');
});

test('D123-④: 全测完时不产出该段（不渲染 0 噪声）', () => {
  const points = [pt('a', 'url', 'id'), pt('b', 'header', 'UA')];
  const r = summarizeUnverifiedSurfaces({ points, fullyTested: ['a', 'b'] });
  assert.equal(r.totalUnverified, 0);
  assert.deepEqual(r.surfaces, []);
  assert.equal(unverifiedSentence(r), null, '无未验证面 ⇒ 不给文案，调用方据此不渲染');
});

test('D123-⑤: 结论文案把「没测成」与「测了没洞」分开说', () => {
  const r = summarizeUnverifiedSurfaces({
    points: [pt('a', 'header', 'UA'), pt('b', 'header', 'Referer'), pt('c', 'url', 'id')],
    fullyTested: ['c'],
    inconclusivePoints: ['a', 'b'],
  });
  const s = unverifiedSentence(r);
  assert.ok(s.includes('2 个注入点未能完成有效检测'), `应给出未验证点数：${s}`);
  assert.ok(s.includes('HTTP 请求头 2/2'), `应按面给出比例：${s}`);
  assert.ok(s.includes('不等于「无漏洞」'), '必须点明与「无漏洞」的区别');
  assert.ok(s.includes('根本没测成'), '必须说清是没测成，而非测后判安全');
});

test('D123-⑥: 网络层失败与拦截中止在 reason 里可区分（对症下药）', () => {
  const points = [pt('a', 'url', 'id'), pt('b', 'url', 'q')];
  const r = summarizeUnverifiedSurfaces({
    points,
    fullyTested: [],
    inconclusivePoints: ['a', 'b'],
    netErrPoints: ['b'],
  });
  const row = r.surfaces.find((x) => x.surface === 'url');
  assert.ok(row.reason.includes('拦截'), `应点名拦截：${row.reason}`);
  assert.ok(row.reason.includes('网络层失败'), `应点名网络失败：${row.reason}`);
});

test('D123-⑦: 空输入不抛、返回空结果（守卫故障不得影响主流程）', () => {
  assert.deepEqual(summarizeUnverifiedSurfaces().surfaces, []);
  assert.equal(summarizeUnverifiedSurfaces({}).totalUnverified, 0);
  assert.equal(unverifiedSentence(null), null);
  assert.equal(unverifiedSentence({ surfaces: [] }), null);
});
