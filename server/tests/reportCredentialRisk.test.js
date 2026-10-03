// 报告侧的「凭据风险」章节单测（--passwords 的解读落进 md / html 交付物）
// 关注两件事：① 有分析结果才渲染，且排在修复建议之前（md/html 同序）；
//            ② 账号名/主机名是**目标可控输入** —— 必须过转义出口（mdCell / esc）。
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { ReportGenerator } from '../src/services/ReportGenerator.js';

const rg = new ReportGenerator();

const RAW_MD5 = 'md5' + 'a'.repeat(32);
const RAW = `evil@h:,bob:${RAW_MD5}`;

/** 手工构造的 passwordAnalysis（形态与 engine/extraction/hashAnalysis.js 一致） */
function mkAnalysis(overrides = {}) {
  return {
    total: 2,
    blank: 1,
    weak: 1,
    medium: 0,
    strong: 0,
    unknown: 0,
    algorithms: { none: 1, 'pg-md5': 1 },
    entries: [
      // 账号名/主机名刻意塞入 HTML 与 markdown 的攻击面：尖括号、竖线
      { identity: 'evil@h', user: '<img src=x onerror=alert(1)>', host: 'a|b', algo: 'none', label: '空', strength: 'blank', risk: 'high' },
      { identity: 'bob', user: 'bob', host: null, algo: 'pg-md5', label: 'PostgreSQL md5（MD5(口令+用户名)，无盐）', strength: 'weak', risk: 'high' },
    ],
    truncated: 0,
    ...overrides,
  };
}

function mkReport(analysis) {
  return rg.build(
    's1',
    { baseUrl: 'http://x' },
    [],
    [],
    {
      databases: [],
      tables: {},
      columns: {},
      rows: {},
      passwords: RAW,
      passwordAnalysis: analysis,
    }
  );
}

test('toMarkdown: 有分析结果 ⇒ 渲染凭据风险章节并给统计', () => {
  const md = rg.toMarkdown(mkReport(mkAnalysis()));
  assert.match(md, /## 凭据风险（--passwords）/);
  assert.match(md, /解析到 2 个账号的凭据/);
  assert.match(md, /未设口令\/非口令插件 1/);
  assert.match(md, /算法分布：none × 1/);
  // 判定口径必须随行出现（「弱」不等于「已破解」这句不能只在代码注释里）
  assert.match(md, /不代表口令已被还原/);
});

test('toMarkdown: 无分析结果 ⇒ 整段不渲染（不留空标题）', () => {
  const md = rg.toMarkdown(rg.build('s1', { baseUrl: 'http://x' }, [], [], null));
  assert.ok(!md.includes('凭据风险'), '无 --passwords 结果时不应出现该章节');
});

test('toHTML: 有分析结果 ⇒ 渲染凭据风险卡（含 bad 高亮）', () => {
  const html = rg.toHTML(mkReport(mkAnalysis()));
  assert.match(html, /凭据风险（--passwords）/);
  assert.match(html, /解析到 2 个账号的凭据/);
  assert.match(html, /class="verdict bad"/, '存在空口令/弱哈希时应高亮');
});

test('toHTML: 无分析结果 ⇒ 不渲染该卡', () => {
  const html = rg.toHTML(rg.build('s1', { baseUrl: 'http://x' }, [], [], null));
  assert.ok(!html.includes('凭据风险'));
});

test('★安全★ 账号名/主机名是目标可控输入：md 侧必须掐掉裸 HTML 并转义竖线', () => {
  const md = rg.toMarkdown(mkReport(mkAnalysis()));
  assert.ok(!md.includes('<img src=x'), 'markdown 不得保留裸 HTML 标签');
  assert.match(md, /&lt;img src=x/, '尖括号应被转义成实体');
  assert.match(md, /a\\\|b/, '单元格里的竖线必须转义，否则整张表被切列');
});

test('★安全★ HTML 侧账号名必须转义（否则报告在读者浏览器里执行脚本）', () => {
  const html = rg.toHTML(mkReport(mkAnalysis()));
  assert.ok(!html.includes('<img src=x'), 'HTML 不得出现未转义标签');
  assert.match(html, /&lt;img src=x onerror=alert\(1\)&gt;/);
});

test('★安全★ 不回显原始哈希（本节不得成为凭据的第二份副本）', () => {
  const md = rg.toMarkdown(mkReport(mkAnalysis()));
  const html = rg.toHTML(mkReport(mkAnalysis()));
  assert.ok(!md.includes(RAW_MD5), 'markdown 不应包含原始哈希串');
  assert.ok(!html.includes(RAW_MD5), 'HTML 不应包含原始哈希串');
});

test('章节顺序：md/html 都在漏洞清单之后、修复建议之前（两格式同序）', () => {
  const report = mkReport(mkAnalysis());
  const md = rg.toMarkdown(report);
  const iMdList = md.indexOf('## 漏洞清单');
  const iMdCred = md.indexOf('## 凭据风险');
  const iMdFix = md.indexOf('## 修复建议');
  assert.ok(iMdList > 0 && iMdCred > iMdList && iMdFix > iMdCred, `md 顺序错：list=${iMdList} cred=${iMdCred} fix=${iMdFix}`);

  const html = rg.toHTML(report);
  const iHList = html.indexOf('<h2>漏洞清单</h2>');
  const iHCred = html.indexOf('凭据风险（--passwords）');
  const iHFix = html.indexOf('<h2>修复建议（Remediation）</h2>');
  assert.ok(iHList > 0 && iHCred > iHList && iHFix > iHCred, `html 顺序错：list=${iHList} cred=${iHCred} fix=${iHFix}`);
});

test('强哈希占多数时不出现「坏结论」高亮文案（避免噪声告警）', () => {
  const allStrong = mkAnalysis({
    total: 1,
    blank: 0,
    weak: 0,
    medium: 0,
    strong: 1,
    unknown: 0,
    algorithms: { bcrypt: 1 },
    entries: [{ identity: 'a', user: 'a', host: null, algo: 'bcrypt', label: 'bcrypt（加盐 + 可调代价）', strength: 'strong', risk: 'low' }],
  });
  const md = rg.toMarkdown(mkReport(allStrong));
  assert.match(md, /未发现空口令 \/ 弱哈希 \/ 未识别格式/);
  const html = rg.toHTML(mkReport(allStrong));
  assert.ok(!html.includes('class="verdict bad"'), '全强哈希不应高亮为 bad');
});
