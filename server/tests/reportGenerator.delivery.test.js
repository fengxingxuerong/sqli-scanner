// [2026-09-13] 报告交付层契约测试：渗透交付物四要素
//   ① 报告元信息（起止/耗时/请求总数/测试范围/授权声明）
//   ② 执行摘要（含拖库影响实证）
//   ③ WAF 交战记录（厂商/被拦数/处置）
//   ④ 修复建议 + CVSS（markdown/html/csv 三侧同源 reportDelivery）
// 交付口径：这四要素缺失的报告会被客户打回（无整改依据、无管理层视图）。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ReportGenerator } from '../src/services/ReportGenerator.js';
import { buildDelivery, cvssFor, severityOf, dataImpactOf, GENERAL_REMEDIATION } from '../src/services/reportDelivery.js';

const rg = new ReportGenerator();

// 最小可用报告：1 注入点 + union/boolean 双通道漏洞 + 拖库树 + validity/WAF 摘要
function mkReport(overrides = {}) {
  return {
    scanId: 's1',
    riskLevel: 'Critical',
    dbms: 'PostgreSQL',
    startedAt: '2026-09-13T06:00:00.000Z',
    finishedAt: '2026-09-13T06:00:30.000Z',
    target: { baseUrl: 'http://127.0.0.1:8130/items?cat=1', config: { level: 3, risk: 2, techniques: ['union', 'error', 'boolean', 'time'] } },
    points: [{ id: 'p1' }],
    vulns: [
      { pointId: 'p1', technique: 'union', dbms: 'PostgreSQL', riskLevel: 'High', payloads: ["1 UNION SELECT NULL,'X'-- -"], description: 'UNION 注入成功' },
      { pointId: 'p1', technique: 'boolean', dbms: 'PostgreSQL', riskLevel: 'Medium', payloads: [], description: '布尔注入确认' },
    ],
    data: { databases: ['postgres'], tables: { 'postgres.users': [] }, rows: { 'postgres.users': [{ id: '1', username: 'alice' }] } },
    summary: {
      validity: { status: 'ok', reliable: true, reason: '累计 95 次请求，无拦截', counts: { total: 95, blockHits: 0 } },
      dbmsEvidence: { dbms: 'PostgreSQL', level: 'verified', levelText: '真实引擎验证' },
      blockPolicy: { action: 'none', reason: '无拦截证据' },
      ...overrides.summary,
    },
    ...overrides,
  };
}

test('buildDelivery: 元信息含耗时/请求总数/测试范围', () => {
  const d = buildDelivery(mkReport());
  assert.equal(d.meta.durationText, '30.0s');
  assert.equal(d.meta.requestCount, 95);
  assert.match(d.meta.scope, /同源/);
  assert.equal(d.meta.level, 3);
  assert.equal(d.meta.techniques, 'union/error/boolean/time');
});

test('buildDelivery: 缺字段全程容错（最小报告不抛错）', () => {
  const d = buildDelivery({});
  assert.equal(d.meta.scanId, '-');
  assert.equal(d.meta.requestCount, null);
  assert.equal(d.exec.impact, null);
  assert.equal(d.exec.vulnCount, 0);
  assert.equal(d.waf.engaged, false);
  assert.ok(d.remediation.general.length >= 4);
});

test('cvssFor: 按技术通道映射且确定性可复算', () => {
  assert.equal(cvssFor({ technique: 'stacked' }).score, 9.8);
  assert.equal(cvssFor({ technique: 'stacked' }).severity, 'Critical');
  assert.equal(cvssFor({ technique: 'union' }).score, 8.2);
  assert.equal(cvssFor({ technique: 'boolean' }).score, 7.5);
  // 未知技术 → 保守默认，不抛错
  assert.equal(cvssFor({ technique: 'suspicious' }).score, 5.3);
  assert.equal(cvssFor({}).score, 5.3);
  // 确定性：同输入同输出
  assert.deepEqual(cvssFor({ technique: 'union' }), cvssFor({ technique: 'union' }));
  // 向量串口径：环境项未设
  assert.match(cvssFor({ technique: 'union' }).vector, /^AV:N\/AC:L\/PR:N\/UI:N\/S:U\//);
});

test('severityOf: CVSS v3.1 官方分段', () => {
  assert.equal(severityOf(9.8), 'Critical');
  assert.equal(severityOf(7.0), 'High');
  assert.equal(severityOf(4.0), 'Medium');
  assert.equal(severityOf(3.9), 'Low');
});

test('dataImpactOf: 汇总表数/行数/样例表名；空树返回 null', () => {
  const impact = dataImpactOf({ rows: { 'postgres.users': [{ id: '1' }, { id: '2' }], 'postgres.orders': [{ id: '1' }] } });
  assert.equal(impact.tableCount, 2);
  assert.equal(impact.rowCount, 3);
  assert.deepEqual(impact.sampleTables, ['postgres.users', 'postgres.orders']);
  assert.equal(dataImpactOf({ rows: {} }), null);
  assert.equal(dataImpactOf(null), null);
});

test('toMarkdown: 四要素章节齐全（元信息/执行摘要/修复建议/WAF 交战）', () => {
  const md = rg.toMarkdown(mkReport());
  for (const section of ['## 报告元信息', '## 执行摘要', '## 修复建议（Remediation）', '### 通用加固基线', '## WAF 交战记录']) {
    assert.ok(md.includes(section), `markdown 缺章节: ${section}`);
  }
  // 执行摘要含影响实证（拖库树 1 行 1 表）
  assert.match(md, /影响实证.*1 张表 \/ 1 行数据.*postgres\.users/s);
  // 元信息含耗时与请求总数
  assert.match(md, /耗时 30\.0s/);
  assert.match(md, /请求总数：95/);
  // 既有行保持：漏洞表加 CVSS 列但原列仍在
  // [2026-09-17] 新增「受影响参数」「漏洞类型」两列（交付缺口：此前只有内部 pointId hash）
  assert.match(md, /\| 注入点 \| 受影响参数 \| 漏洞类型 \| 技术 \| 数据库 \| 风险 \| CVSS \| 说明 \|/);
  assert.match(md, /CVSS 8\.2 High.*AV:N\/AC:L\/PR:N\/UI:N\/S:U\/C:H\/I:L\/A:N/s);
  // 通用基线含参数化与最小权限（整改可执行性）
  assert.ok(GENERAL_REMEDIATION.some((a) => a.includes('参数化')));
  assert.ok(GENERAL_REMEDIATION.some((a) => a.includes('最小权限')));
});

test('toMarkdown: 0 漏洞报告同样渲染四要素且不抛错', () => {
  const md = rg.toMarkdown(mkReport({ vulns: [], data: null, riskLevel: 'Low', dbms: null }));
  assert.match(md, /未检出漏洞/);
  assert.match(md, /## 报告元信息/);
  assert.match(md, /## 修复建议（Remediation）/);
  assert.match(md, /## WAF 交战记录/);
});

test('toHTML: 四要素章节齐全且表格 CVSS 列落位', () => {
  const html = rg.toHTML(mkReport());
  for (const section of ['报告元信息', '执行摘要', '修复建议（Remediation）', 'WAF 交战记录']) {
    assert.ok(html.includes(section), `html 缺章节: ${section}`);
  }
  assert.match(html, /<th>CVSS<\/th>/);
  assert.match(html, /8\.2 High/);
  assert.match(html, /影响实证/);
  // 既有合规页脚仍在
  assert.match(html, /本报告仅供授权安全测试使用/);
});

test('toHTML: WAF engaged 时显示处置与 tamper 线索', () => {
  const html = rg.toHTML(
    mkReport({
      summary: {
        validity: { status: 'ok', reliable: true, counts: { total: 50, blockHits: 12 } },
        wafDetected: [{ vendor: 'ModSecurity', confidence: 0.9 }],
        blockPolicy: { action: 'retryTamper', reason: '有拦截证据', tamperHint: ['space2comment', 'charencode'] },
      },
    })
  );
  assert.match(html, /ModSecurity/);
  assert.match(html, /retryTamper/);
  assert.match(html, /space2comment/);
});

test('toCSV: CVSS 与修复建议列落位（三侧同源）', () => {
  // CSV 以 BOM 开头（Excel 中文兼容），断言前剥掉
  const csv = rg.toCSV(mkReport()).replace(/^\uFEFF/, '');
  // [2026-09-17] 新增受影响参数/漏洞类型/CWE/OWASP/受影响请求列（原列相对顺序不变）
  assert.match(csv, /^漏洞ID,注入点,受影响参数,漏洞类型,CWE,OWASP,技术,数据库,风险,CVSS,受影响请求,修复建议,说明/);
  assert.match(csv, /8\.2/);
  assert.match(csv, /参数化/);
});

test('toMarkdown: 同一份报告两次渲染逐字节一致（CLI md/markdown 等价口径）', () => {
  const report = mkReport();
  assert.equal(rg.toMarkdown(report), rg.toMarkdown(report));
});

test('toMarkdown: 缺 startedAt/finishedAt 时耗时降级为 -（不 NaN）', () => {
  const md = rg.toMarkdown(mkReport({ startedAt: undefined, finishedAt: undefined }));
  assert.ok(!md.includes('NaN'));
  assert.match(md, /耗时 -/);
});

// ============================================================================
// [2026-09-17] 交付缺口回归：漏洞条目必须自带「受影响参数」与「漏洞类型(CWE/OWASP)」
// 缺陷背景：漏洞对象此前只有 pointId——一个内部 hash（sha256 前 8 位），报告里的漏洞表、
// 修复建议、PoC 标题全部只印这串 hash，客户拿着报告无法对应到「哪个参数中招、这是什么漏洞」。
// 本组用例锁住三件已交付的能力：①三侧表格新增列真实渲染取值；②修复建议/PoC 标题可对应参数；
// ③字段缺失时降级为显式标注而非空单元格（空单元格会被读成「无影响」）。
// ============================================================================

// 带完整注入点上下文的报告（mkReport 的 points 只有 id，用于覆盖降级路径）
function mkReportWithParam(overrides = {}) {
  const r = mkReport(overrides);
  r.points = [{ id: 'p1', location: 'url', param: 'cat', originalValue: '1' }];
  r.target = { baseUrl: 'http://127.0.0.1:8130/items?cat=1', method: 'GET', config: {} };
  return r;
}

test('漏洞表新增列：受影响参数 + 漏洞类型(CWE) 在 markdown/html/csv 三侧同源渲染', () => {
  const report = mkReportWithParam();
  const md = rg.toMarkdown(report);
  assert.match(md, /\| p1 \| cat · URL 查询参数（GET query） \| SQL 注入（联合查询注入） · CWE-89 \| union \| PostgreSQL \|/);

  const html = rg.toHTML(report);
  assert.match(html, /<th>受影响参数<\/th>/);
  assert.match(html, /<th>漏洞类型<\/th>/);
  assert.match(html, /cat · URL 查询参数（GET query）/);
  assert.match(html, /SQL 注入（联合查询注入） · CWE-89/);

  const csv = rg.toCSV(report).replace(/^\uFEFF/, '');
  assert.match(csv, /"cat · URL 查询参数（GET query）"/);
  assert.match(csv, /"SQL 注入（联合查询注入）"/);
  assert.match(csv, /"CWE-89"/);
  assert.match(csv, /"A03:2021-Injection"/);
  assert.match(csv, /"GET http:\/\/127\.0\.0\.1:8130\/items\?cat=1"/); // 受影响请求
});

test('漏洞条目自包含：JSON 段落带 param/location/url/method/vulnType（脱报告可读）', () => {
  const json = JSON.parse(rg.toJSON(mkReportWithParam()));
  const v = json.vulns[0];
  assert.equal(v.param, 'cat');
  assert.equal(v.location, 'url');
  assert.equal(v.url, 'http://127.0.0.1:8130/items?cat=1');
  assert.equal(v.method, 'GET');
  assert.match(v.affectedParam, /^cat · /);
  assert.equal(v.vulnType.cwe, 'CWE-89');
  assert.equal(v.vulnType.nameZh, 'SQL 注入（联合查询注入）');
});

test('修复建议与 PoC 标题可对应到具体参数（不再只有内部 pointId）', () => {
  const report = mkReportWithParam();
  const md = rg.toMarkdown(report);
  assert.match(md, /\*\*p1 · cat · URL 查询参数（GET query） · union · CVSS 8\.2 High\*\*/);
  assert.match(md, /### PoC-1-1 · 注入点 p1（参数 cat） · union · 主命中/);

  const html = rg.toHTML(report);
  assert.match(html, /p1<\/b> · cat · URL 查询参数（GET query）/);
});

test('缺注入点上下文时降级为显式标注（不产出空单元格、不抛错）', () => {
  const md = rg.toMarkdown(mkReport()); // points 只有 id，无 param
  assert.match(md, /\| p1 \| （未记录参数名） · 未知位置 \|/);
  assert.ok(!md.includes('| p1 |  |'), '空单元格会被读成「无影响」，必须显式标注');
});
