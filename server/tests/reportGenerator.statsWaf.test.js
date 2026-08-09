import test from 'node:test';
import assert from 'node:assert/strict';
import { ReportGenerator } from '../src/services/ReportGenerator.js';

const gen = new ReportGenerator();

const normalVuln = {
  id: 'v1',
  pointId: 'p1',
  technique: 'boolean',
  dbms: 'MySQL',
  riskLevel: 'Medium',
  payloads: ["1' AND 1=1-- -"],
  description: '布尔盲注确认',
};

test('toHTML 渲染扫描统计（技术/风险分布）', () => {
  const html = gen.toHTML({
    scanId: 's5',
    riskLevel: 'High',
    dbms: 'MySQL',
    target: { baseUrl: 'http://t/' },
    points: [{ id: 'p1' }],
    vulns: [normalVuln],
    summary: { byTechnique: { boolean: 1, time: 2 }, byRisk: { Medium: 2, High: 1 } },
  });
  assert.match(html, /扫描统计/);
  assert.match(html, /按技术：/);
  assert.match(html, /boolean:1/);
  assert.match(html, /按风险：/);
  assert.match(html, /High:1/);
});

test('toHTML 渲染 WAF 规避与指纹标注', () => {
  const html = gen.toHTML({
    scanId: 's6',
    riskLevel: 'Low',
    dbms: null,
    target: { baseUrl: 'http://t/' },
    points: [],
    vulns: [],
    summary: {
      wafEvasion: {
        tamper: { enabled: true, plugins: ['space2comment', 'charencode'], intensity: 'high' },
      },
      wafDetected: [{ vendor: 'Cloudflare', confidence: 0.92 }],
    },
  });
  assert.match(html, /WAF 规避与指纹/);
  assert.match(html, /space2comment → charencode/);
  assert.match(html, /Cloudflare\(0\.92\)/);
});

test('toHTML 无 WAF 信息时不渲染 WAF 区块', () => {
  const html = gen.toHTML({
    scanId: 's7',
    riskLevel: 'Low',
    dbms: null,
    target: { baseUrl: 'http://t/' },
    points: [],
    vulns: [],
    summary: {},
  });
  assert.doesNotMatch(html, /WAF 规避与指纹/);
});
