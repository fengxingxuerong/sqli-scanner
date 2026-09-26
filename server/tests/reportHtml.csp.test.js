// ============================================================================
// reportHtml.csp.test.js —— 交付 HTML 的结构不变量（CSP + 标签级无脚本面）
// ============================================================================
// 报告的防御目前是**逐点转义**（esc / mdText / safeHref 各管一处）。这类防线的失效方式是
// "以后有人新增一个出口忘了调"，而一旦漏，后果是目标可控字符串在**读者的浏览器**里执行。
// 本文件不测"转义有没有调对"（那是 reportExport.hostile.test.js 的活），它测的是
// **整份文档的结构**：不管内容怎么变，交付 HTML 里都不该出现可执行的面。
// 加 CSP 是把"单点漏转义 = 任意脚本执行"降级成"某个标签渲染不出来"的结构性第二道门。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ReportGenerator } from '../src/services/ReportGenerator.js';
import { REPORT_CSP_META } from '../src/services/reportHtml.js';

const rg = new ReportGenerator();
const IMG = 'a<img src=x onerror=alert(document.domain)>b';
const SVG = '1`<svg onload=alert(document.domain)>';

function hostileReport() {
  const target = { url: 'http://shop.example.com/item?id=1', method: 'GET', query: { id: '1' } };
  const point = { id: 'p1', location: 'url', param: IMG, originalValue: '1' };
  const vuln = {
    pointId: 'p1', technique: 'union', dbms: 'MySQL', riskLevel: 'High', param: IMG,
    payloads: [SVG], evidencePayload: SVG, url: 'http://shop.example.com/item?id=1', method: 'GET', description: 'x',
  };
  const data = { databases: ['l'], rows: { 'users`x': [{ nickname: IMG, id: '1' }] } };
  return rg.build('scsp', target, [point], [vuln], data);
}

const HTML = rg.toHTML(hostileReport());

/** 抽出文档里**真正的起始标签**（含属性），转义过的内容形不成标签 */
function startTags(html) {
  const re = /<([a-zA-Z][a-zA-Z0-9]*)((?:\s+[^\s"'>\/=]+(?:\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+))?)*)\s*\/?>/g;
  const out = [];
  let m;
  while ((m = re.exec(html))) out.push({ tag: m[1].toLowerCase(), attrs: m[2] || '' });
  return out;
}

const ATTR_RE = /([^\s"'>\/=]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+)))?/g;
function attrsOf(raw) {
  const list = [];
  let m;
  while ((m = ATTR_RE.exec(raw))) list.push({ name: m[1].toLowerCase(), value: m[2] ?? m[3] ?? m[4] ?? '' });
  return list;
}

test('反空转前提：不可信内容确实出现在了这份 HTML 里（不是靠"内容被丢掉"变绿的）', () => {
  assert.ok(HTML.includes('onerror=alert(document.domain)'), 'payload/参数名必须仍在文档中（以转义后的文本形态）');
  assert.ok(HTML.includes('&lt;img') || HTML.includes('&lt;svg'), '应看到实体化后的标签，说明数据进来了而没被吞');
});

test('交付 HTML 带 CSP，且 default-src 收紧到 none', () => {
  assert.match(HTML, /<meta http-equiv="Content-Security-Policy"/);
  assert.match(HTML, /default-src 'none'/);
  assert.match(HTML, /style-src 'unsafe-inline'/, '报告样式与 SVG 的 style 属性是内联的，策略必须自带放行');
});

test('CSP 不写 meta 里会被浏览器忽略的指令（避免"看着有实际没有"的错觉）', () => {
  for (const ignored of ['frame-ancestors', 'sandbox', 'report-uri']) {
    assert.ok(!REPORT_CSP_META.includes(ignored), `${ignored} 在 meta 传递里被规范忽略，写上去是误导`);
  }
});

test('结构不变量：文档里没有任何可执行面（script/事件属性/危险协议/外发容器）', () => {
  const tags = startTags(HTML);
  assert.ok(tags.length > 10, `只解析出 ${tags.length} 个标签 —— 解析正则失效，本守卫不得空转`);
  const BANNED_TAGS = new Set(['script', 'iframe', 'frame', 'object', 'embed', 'form', 'base']);
  const problems = [];
  for (const { tag, attrs } of tags) {
    if (BANNED_TAGS.has(tag)) problems.push(`<${tag}> 出现在交付报告里`);
    for (const a of attrsOf(attrs)) {
      if (/^on[a-z]+$/.test(a.name)) problems.push(`<${tag}> 带事件属性 ${a.name}=`);
      if (['href', 'src', 'xlink:href', 'action', 'data', 'srcdoc'].includes(a.name)) {
        const v = a.value.trim().toLowerCase();
        if (v.startsWith('javascript:') || v.startsWith('vbscript:') || v.startsWith('data:text/html')) {
          problems.push(`<${tag}> ${a.name}="${a.value}" 是可执行协议`);
        }
      }
    }
  }
  assert.deepEqual(problems, [], problems.join('\n'));
});

test('结构不变量：外链只允许 http/https/data:，且内网地址不会变成可点链接', () => {
  for (const { tag, attrs } of startTags(HTML)) {
    if (tag !== 'a') continue;
    const href = attrsOf(attrs).find((a) => a.name === 'href');
    if (!href) continue;
    assert.match(href.value, /^(https?:|data:|#)/i, `<a href="${href.value}"> 不在允许的协议面内`);
  }
  // 参数名/表名这类目标可控文本必须成实体（若哪天退化成裸标签，上面几支会红，这里补一刀定位）
  assert.ok(!/<a[^>]+127\.0\.0\.1/i.test(HTML), '回环地址不得作为链接出现');
});

test('同一份报告的 HTML 多次导出逐字节一致（CSP 注入不得引入不稳定输出）', () => {
  const report = hostileReport();
  assert.equal(rg.toHTML(report), rg.toHTML(report));
});
