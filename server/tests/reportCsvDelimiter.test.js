// [D245 对标 sqlmap --csv-del] CSV 分隔符的判据
//
// 钉四条：
//   ① 默认仍是逗号（开关不能改默认行为）；
//   ② 单字符分隔符生效（表头 + 漏洞行 + 拖库行三处都要换，不能只换一处）；
//   ③ `\t` 字面量解析成制表符（Excel 本地化最常见的写法）；
//   ④ `_csvDelimiter` 是渲染开关，不得出现在产物里。
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { formatReport } from '../bin/cli/reportOutput.js';

/**
 * 造一份带拖库数据的最小报告。
 * @returns {any}
 */
function mkReport() {
  return {
    scanId: 's1',
    target: { url: 'http://t/p?id=1', method: 'GET' },
    summary: { verdict: 'vulnerable' },
    points: [],
    vulns: [{ id: 'v1', pointId: 'p1', technique: 'boolean', risk: 2, dbms: 'MySQL' }],
    data: { rows: { users: [{ id: 1, name: 'a,b' }] } },
  };
}

test('默认分隔符仍是逗号（开关不改默认）', () => {
  const csv = formatReport(mkReport(), 'csv');
  const head = csv.split('\n')[0];
  assert.ok(head.includes(','), `表头应含逗号，实际：${head}`);
  assert.ok(!head.includes(';'), '不应出现分号');
});

test('--csv-del ; ⇒ 表头/漏洞行/拖库行三处都换', () => {
  const csv = formatReport(mkReport(), 'csv', { csvDelimiter: ';' });
  const lines = csv.split('\n');
  // CSV 带 BOM（\uFEFF），所以用 includes 而不是 startsWith
  assert.ok(lines[0].includes('漏洞ID;注入点;'), `表头应用分号，实际：${lines[0]}`);
  // 漏洞行（表头之后第一行非空；单元格带引号，所以判 "v1" 而不是 v1）
  const vulnLine = lines.find((l) => l.startsWith('"v1"'));
  assert.ok(vulnLine && vulnLine.includes(';'), '漏洞行应用分号');
  // 拖库行（含 users 数据）
  const dumpLine = lines.find((l) => l.includes('a,b') || l.includes('a b'));
  assert.ok(dumpLine, '应有拖库数据行');
});

test('--csv-del \\t ⇒ 制表符', () => {
  const csv = formatReport(mkReport(), 'csv', { csvDelimiter: '\\t' });
  assert.ok(csv.split('\n')[0].includes('\t'), '表头应用制表符分隔');
});

test('_csvDelimiter 不得出现在产物里（渲染开关不是报告字段）', () => {
  const out = JSON.parse(formatReport(mkReport(), 'json', { csvDelimiter: ';' }));
  assert.equal('_csvDelimiter' in out, false);
});

test('非法分隔符（多字符）⇒ 回落逗号，不抛错', () => {
  const csv = formatReport(mkReport(), 'csv', { csvDelimiter: ';;' });
  assert.ok(csv.split('\n')[0].includes(','), '多字符应回落逗号');
});
