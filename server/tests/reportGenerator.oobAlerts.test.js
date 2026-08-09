import test from 'node:test';
import assert from 'node:assert/strict';
import { ReportGenerator } from '../src/services/ReportGenerator.js';

const gen = new ReportGenerator();

const oobVuln = {
  id: 'v1',
  pointId: 'p1',
  technique: 'oob',
  dbms: 'MySQL',
  riskLevel: 'Medium',
  payloads: ["1' AND (SELECT LOAD_FILE(...))-- -"],
  description: 'OOB 带外确认：无回显注入成立',
  oob: { token: 'tk_abc123', callback: '127.0.0.1:8899/oob/tk_abc123' },
};
const normalVuln = {
  id: 'v2',
  pointId: 'p2',
  technique: 'boolean',
  dbms: 'MySQL',
  riskLevel: 'Medium',
  payloads: ["1' AND 1=1-- -"],
  description: '布尔盲注确认',
};
const alert = {
  url: 'http://safe1/',
  reason: '状态码偏离：200 → 403',
  baselineStatus: 200,
  baselineLen: 100,
  actualStatus: 403,
  actualLen: 12,
  ts: '2026-08-05T00:00:00Z',
};

test('toHTML 渲染 OOB 命中区块（token + 回连地址）', () => {
  const html = gen.toHTML({
    scanId: 's1',
    riskLevel: 'Medium',
    dbms: 'MySQL',
    target: { baseUrl: 'http://t/' },
    points: [],
    vulns: [oobVuln],
    summary: {},
  });
  assert.match(html, /带外回连确认（OOB）/);
  assert.match(html, /tk_abc123/);
  assert.match(html, /127\.0\.0\.1:8899\/oob\/tk_abc123/);
});

test('toHTML 渲染安全间隔探测告警区块（含每条明细）', () => {
  const html = gen.toHTML({
    scanId: 's2',
    riskLevel: 'Medium',
    dbms: null,
    target: { baseUrl: 'http://t/' },
    points: [],
    vulns: [normalVuln],
    summary: { safeProbeAlerts: [alert] },
  });
  assert.match(html, /安全间隔探测告警（1 条）/);
  assert.match(html, /http:\/\/safe1\//);
  assert.match(html, /基线 200（100B）→ 实际 403（12B）/);
});

test('toHTML 无 OOB/告警时不渲染对应区块', () => {
  const html = gen.toHTML({
    scanId: 's3',
    riskLevel: 'Low',
    dbms: null,
    target: { baseUrl: 'http://t/' },
    points: [],
    vulns: [normalVuln],
    summary: {},
  });
  assert.doesNotMatch(html, /带外回连确认/);
  assert.doesNotMatch(html, /安全间隔探测告警/);
});

test('toJSON 保留 vuln.oob 与 summary.safeProbeAlerts', () => {
  const json = JSON.parse(
    gen.toJSON({
      scanId: 's4',
      vulns: [oobVuln],
      summary: { safeProbeAlerts: [alert] },
    })
  );
  assert.equal(json.vulns[0].oob.token, 'tk_abc123');
  assert.equal(json.summary.safeProbeAlerts[0].url, 'http://safe1/');
});
