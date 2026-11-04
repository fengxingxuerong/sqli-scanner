// [D243 对标 sqlmap --no-truncate] 导出截断开关的判据
//
// 钉三条：
//   ① 默认仍截断到 EVIDENCE_MAX(4000) —— 开关不能把默认行为改掉；
//   ② 开了开关 ⇒ 长 evidence 原样保留（取证场景的全部意义）；
//   ③ `_noTruncate` 是渲染开关，**不得出现在产物里**（否则报告多一个内部字段，
//      下游 schema 校验与"两次渲染逐字节一致"都会受影响）。
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { formatReport } from '../bin/cli/reportOutput.js';

/**
 * 造一份最小可用报告（字段够 _enrich/_attachPoc 走通即可）。
 * @param {number} n evidence 长度
 * @returns {any}
 */
function mkReport(n) {
  return {
    scanId: 's1',
    target: { url: 'http://t/p?id=1', method: 'GET' },
    summary: { verdict: 'vulnerable' },
    points: [],
    vulns: [{ id: 'v1', pointId: 'p1', technique: 'boolean', risk: 2, evidence: 'E'.repeat(n), description: 'D'.repeat(n) }],
  };
}

test('默认：evidence 被截断（开关不能改默认）', () => {
  const out = JSON.parse(formatReport(mkReport(5000), 'json'));
  const ev = out.vulns[0].evidence;
  // truncateLong 的口径是 `slice(0,4000) + '…[截断 N 字符]'`，所以判"有截断标记且远短于原文"
  assert.match(ev, /…\[截断 \d+ 字符\]$/);
  assert.ok(ev.length < 5000, `应短于原文，实际 ${ev.length}`);
});

test('--no-truncate：evidence 原样保留', () => {
  const out = JSON.parse(formatReport(mkReport(5000), 'json', { noTruncate: true }));
  assert.equal(out.vulns[0].evidence.length, 5000);
});

test('_noTruncate 不得出现在产物里（渲染开关不是报告字段）', () => {
  const out = JSON.parse(formatReport(mkReport(10), 'json', { noTruncate: true }));
  assert.equal('_noTruncate' in out, false);
  assert.equal('_noTruncate' in out.vulns[0], false);
});
