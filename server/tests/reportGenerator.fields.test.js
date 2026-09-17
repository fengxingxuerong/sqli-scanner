// ============================================================================
// reportGenerator.fields.test.js —— 「受影响参数 / 漏洞类型」渲染契约与恶意输入边界
// ============================================================================
// 存在理由：这两个字段是新增的交付一等公民，取值直接来自**被测目标**（参数名由对方的
// 页面表单/URL 决定，属不可信输入）。报告是要被人打开、贴进工单、导进 Excel 的——
// 一条没转义的竖线就能把 Markdown 表格切列，一个 `=` 开头的值在 Excel 里就是公式，
// 一段 `<script>` 在 HTML 报告里就是 XSS。**渲染层的边界不是边角料，是交付物的安全性。**
//
// 本文件锁三类契约：
//   ① 恶意/畸形参数名在三侧（Markdown / HTML / CSV）都不破坏结构、不执行（转义）；
//   ② 字段缺失或技术未收录时是**显式降级**而不是空单元格（空会被读成「无影响」）；
//   ③ 确定性：同一份报告多次渲染逐字节一致（含多 payload 场景）。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ReportGenerator } from '../src/services/ReportGenerator.js';

const rg = new ReportGenerator();

function mkReport(vulns, points, target) {
  return {
    scanId: 's1',
    riskLevel: 'High',
    dbms: 'MySQL',
    startedAt: '2026-09-17T00:00:00.000Z',
    finishedAt: '2026-09-17T00:00:10.000Z',
    target: target || { baseUrl: 'http://t.local/p', method: 'GET', config: {} },
    points,
    vulns,
    data: null,
    summary: {},
  };
}

const VULN = (over = {}) => ({
  pointId: 'p1', technique: 'union', riskLevel: 'High',
  payloads: ['1 UNION SELECT NULL-- -'], description: '命中', ...over,
});

/** 取 markdown 中 p1 所在表格行 */
const rowOf = (md) => md.split('\n').find((l) => l.startsWith('| p1 ')) || '';

// ---------------------------------------------------------------------------
// ① 不可信参数名：三侧都不破坏结构
// ---------------------------------------------------------------------------

test('参数名含竖线：Markdown 表格不被切列（分隔符计数仍为 8 列）', () => {
  const md = rg.toMarkdown(mkReport([VULN()], [{ id: 'p1', location: 'url', param: 'a|b' }]));
  const row = rowOf(md);
  assert.ok(row, '应渲染出 p1 行');
  assert.ok(row.includes('a\\|b'), '竖线必须转义，否则整张表被切列');
  // 8 列需要 9 个分隔符；被转义的 \| 是数据不是分隔符，需扣除
  const pipes = (row.match(/\|/g) || []).length;
  const escaped = (row.match(/\\\|/g) || []).length;
  assert.equal(pipes - escaped, 9, `表格应为 8 列（实得 ${pipes - escaped - 1} 列）：${row.slice(0, 120)}`);
});

test('参数名含 HTML：HTML 报告必须转义，不得出现可执行标签', () => {
  const param = '<img src=x onerror=alert(1)>';
  const html = rg.toHTML(mkReport([VULN()], [{ id: 'p1', location: 'url', param }]));
  assert.ok(!/<img src=x/.test(html), '原始标签不得原样落进 HTML');
  assert.ok(html.includes('&lt;img'), '应转义为实体');
  // 只匹配**标签形式**（以 < 开头）。转义后的纯文本里出现 "onerror=" 是正确行为——
  // 那正是要给人看的证据原文，判失败就变成「不许在报告里展示 payload」了。
  assert.ok(!/<[a-z]+[^>]*onerror/i.test(html), '不得存在带事件处理器的标签');
});

test('参数名含引号：HTML 与属性位安全（&quot; / &#39;）', () => {
  const html = rg.toHTML(mkReport([VULN()], [{ id: 'p1', location: 'url', param: `a"b'c&d` }]));
  assert.ok(!/a"b'c&d/.test(html), '裸引号不得原样出现');
  assert.ok(html.includes('&#34;') && html.includes('&#39;'), '引号必须转数字实体（属性位也安全）');
  assert.ok(html.includes('&amp;'), '& 必须转义');
});

test('参数名以 = 开头：CSV 单元格加单引号前缀（防 Excel 公式注入）', () => {
  const param = `=cmd|'/c calc'!A1`;
  const csv = rg.toCSV(mkReport([VULN()], [{ id: 'p1', location: 'url', param }])).replace(/^\uFEFF/, '');
  // 单元格形如 "'=cmd|..."：前缀单引号让 Excel 按文本处理而不是公式
  assert.ok(csv.includes(`"'=cmd`), `CSV 未做公式注入防护：${csv.split('\n')[1]}`);
});

test('参数名含反引号：不提前闭合 Markdown 行内代码', () => {
  const md = rg.toMarkdown(mkReport([VULN()], [{ id: 'p1', location: 'url', param: 'a`b`' }]));
  const row = rowOf(md);
  assert.ok(row.includes('a`b`'), '表格单元格是纯文本不受反引号影响');
  // 表格不应被反引号破坏：仍能在同一行找到该参数
  assert.equal((row.match(/\|/g) || []).length - (row.match(/\\\|/g) || []).length, 9);
});

// ---------------------------------------------------------------------------
// ② 缺失 / 未收录：显式降级，不产空单元格
// ---------------------------------------------------------------------------

test('技术通道未收录：兜底类型仍带 CWE，报告不出现空格子', () => {
  const md = rg.toMarkdown(mkReport([VULN({ technique: 'brand_new_channel' })], [{ id: 'p1', location: 'url', param: 'id' }]));
  assert.match(md, /SQL 注入（未分类通道） · CWE-89/);
  const csv = rg.toCSV(mkReport([VULN({ technique: 'brand_new_channel' })], [{ id: 'p1', location: 'url', param: 'id' }])).replace(/^\uFEFF/, '');
  assert.match(csv, /"SQL 注入（未分类通道）","CWE-89"/);
});

test('无注入点上下文：降级为显式标注而非空白（防被读成「无影响」）', () => {
  const md = rg.toMarkdown(mkReport([VULN()], []));
  assert.match(md, /（未记录参数名）/);
  assert.ok(!/\| p1 \| {2,}\|/.test(md), '不得出现空白单元格');
});

test('直连模式（无 HTTP 参数名）：退化为 SQL 模板标识', () => {
  const points = [{ id: 'p1', location: 'direct', sqlTemplate: 'SELECT 1 FROM t WHERE id={INJECT}' }];
  const md = rg.toMarkdown(mkReport([VULN()], points));
  assert.match(md, /（直连 SQL 模板）/);
});

test('0 漏洞：空态行占满 8 列（列数变更时此处会先炸）', () => {
  const md = rg.toMarkdown(mkReport([], []));
  assert.match(md, /\| - \| - \| - \| - \| - \| - \| - \| 未发现漏洞 \|/);
});

// ---------------------------------------------------------------------------
// ③ 确定性与体量控制
// ---------------------------------------------------------------------------

test('多 payload：PoC 逐条展开且共用同一时间戳（两次渲染逐字节一致）', () => {
  const r = mkReport(
    [VULN({ payloads: ['payload-a', 'payload-b', 'payload-c'] })],
    [{ id: 'p1', location: 'url', param: 'id' }]
  );
  const first = rg.toMarkdown(r);
  // 「生成时间」在报告元信息小节也有一行，必须只统计 PoC 小节内的，否则计数恒多 1
  const pocSection = (first.split('## 复现方式（PoC）')[1] || '');
  const times = pocSection.match(/- 生成时间：([^\n]+)/g) || [];
  assert.equal(times.length, 3, `三条 payload 应展开为 3 条 PoC（实得 ${times.length}）`);
  assert.equal(new Set(times).size, 1, '同批证据必须共用同一时间戳');
  assert.equal(first, rg.toMarkdown(r), '同一份报告两次渲染必须逐字节一致');
});

test('超长证据：按 EVIDENCE_MAX 截断，不把报告撑爆', () => {
  const md = rg.toMarkdown(mkReport([VULN({ description: 'x'.repeat(9000) })], [{ id: 'p1', location: 'url', param: 'id' }]));
  const row = rowOf(md);
  assert.ok(row.length < 6000, `证据应被截断（行长得 ${row.length}）`);
});

test('HTML 与 Markdown 两侧受影响参数取值同源（不漂移）', () => {
  const r = mkReport([VULN()], [{ id: 'p1', location: 'body', param: 'q' }]);
  const html = rg.toHTML(r);
  const md = rg.toMarkdown(r);
  assert.match(md, /q · 请求体参数/);
  assert.match(html, /q · 请求体参数/);
});
