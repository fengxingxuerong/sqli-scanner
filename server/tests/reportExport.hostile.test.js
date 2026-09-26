// ============================================================================
// reportExport.hostile.test.js —— 「目标可控数据」打穿报告出口的守卫
// ============================================================================
// 威胁模型（与前几轮 htmlSanitize / CSV 公式防护同一条线）：
//   报告是**交付物**，读者会在自己的机器上打开 .md / .csv —— 而报告里的参数名、
//   payload、表名列名全部由**被测目标**决定（参数名来自目标页面，表名列名来自目标的
//   information_schema）。所以「目标 → 阅读报告的机器」是一条真实的攻击路径，
//   与「目标 → 扫描器」同级。
//
// 本文件钉住三条历史上真实存在的断口（每条都先复现再修）：
//   ① markdown **正文位**输出裸 HTML（.md 经 pandoc / markdown-it / GitHub 渲染时
//      默认保留行内原始 HTML → onerror 在读者浏览器里执行）；
//   ② markdown **代码位**用反斜杠转义反引号 —— CommonMark 规定行内代码里反斜杠
//      无转义含义，于是 payload 里的一个 ` 让围栏提前闭合，后半段掉回正文；
//   ③ CSV 拖库区块：列头没过 csvSafeCell（最后一处无守卫出口），区块标题行内插表名
//      （名字里带 \n 或 , 就能凭空造出一个以 = 开头的单元格）。
//   ④ 内网地址判定被 IPv6 字面量绕过（URL 会把 ::ffff:127.0.0.1 规范化成
//      ::ffff:7f00:1，点分正则永远匹配不上）→ 报告里留下可点击的回环链接。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ReportGenerator } from '../src/services/ReportGenerator.js';
import { attackPathMarkdown } from '../src/services/reportAttackPath.js';
import { isInternalHost } from '../src/services/reportHtml.js';

const rg = new ReportGenerator();

const HOSTILE_PARAM = 'a<img src=x onerror=alert(document.domain)>b';
const HOSTILE_PAYLOAD = '1`<svg onload=alert(document.domain)>`';
const HOSTILE_TABLE = 'users\n=HYPERLINK("http://evil.example","pwn")';
const HOSTILE_COL = '=cmd|\' /C calc\'!A0';

function hostileReport() {
  const target = { url: 'http://shop.example.com/item?id=1', method: 'GET', query: { id: '1' } };
  const point = { id: 'p1', location: 'url', param: HOSTILE_PARAM, originalValue: '1' };
  const vuln = {
    pointId: 'p1',
    technique: 'union',
    dbms: 'MySQL',
    riskLevel: 'High',
    param: HOSTILE_PARAM,
    payloads: [HOSTILE_PAYLOAD],
    evidencePayload: HOSTILE_PAYLOAD,
    description: 'x',
  };
  const data = {
    databases: ['sqli_lab'],
    rows: { [HOSTILE_TABLE]: [{ [HOSTILE_COL]: 'v', id: '1' }] },
  };
  return rg.build('shostile', target, [point], [vuln], data);
}

// 一条 HTML 标签：`<` + 字母/斜杠 起头即算（正文位里出现就说明能被解析成标签）
const RAW_TAG = /<[a-zA-Z/!/]/;

// markdown 里**真正会被当 HTML 解析**的位置 = 去掉行内代码、去掉围栏代码块后的正文。
// 行内代码/围栏内的 `<svg` 是安全的（渲染器一律转义代码位），把它们算进来会让本守卫
// 变成「报告里不许出现尖括号」这种无意义断言；但 ```mermaid 必须保留 —— mermaid 的
// htmlLabels 会把标签**照常渲染**，那正是本报告出口的可达面。
function markdownHtmlPositions(md) {
  const kept = [];
  let fence = null; // { mark: '```', mermaid: boolean }
  for (const line of md.split(/\r?\n/)) {
    if (fence) {
      if (line.trimStart().startsWith(fence.mark) && line.trim() === fence.mark) fence = null;
      else if (fence.mermaid) kept.push(line); // mermaid 正文仍要判
      continue;
    }
    const open = line.match(/^(`{3,})(\w*)/);
    if (open) {
      fence = { mark: open[1], mermaid: open[2] === 'mermaid' };
      continue;
    }
    kept.push(line.replace(/(`+)[\s\S]*?\1/g, '')); // 剥掉行内代码
  }
  return kept.join('\n');
}

test('① markdown 正文位不得出现裸 HTML（参数名 / PoC 标题 / 修复建议 / mermaid 标签）', () => {
  const md = rg.toMarkdown(hostileReport());
  const positions = markdownHtmlPositions(md);
  const hits = positions.split(/\r?\n/).filter((l) => RAW_TAG.test(l));
  assert.deepEqual(hits, [], `markdown 正文位存在未转义的 HTML 起始标签：\n${hits.join('\n')}`);
  assert.match(md, /&lt;img/, '参数名应转成实体后仍在报告里（可读性不损）');
});

test('② 含反引号的 payload 不会提前闭合行内代码（围栏长度由内容决定）', () => {
  const md = rg.toMarkdown(hostileReport());
  const line = md.split(/\r?\n/).find((l) => l.startsWith('- Payload：'));
  assert.ok(line, 'PoC 的 Payload 行必须存在');
  // 围栏必须是「比内容里最长反引号串更长」的连续反引号，且首尾成对
  const fence = (line.match(/`+/g) || []).reduce((m, r) => Math.max(m, r.length), 0);
  assert.ok(fence >= 2, `围栏长度 ${fence} 不足以包住内容里的反引号串`);
  assert.match(line, /^- Payload：`{2,}[\s\S]*`{2,}$/, '行内代码必须整段闭合，不得有半截掉回正文');
  // 关键判据：剥掉行内代码后，这一行不能再留下任何正文位内容
  assert.equal(line.replace(/(`+)[\s\S]*?\1/g, ''), '- Payload：', 'payload 有半截落在代码位之外');
});

test('③ 目标数据里的换行不得改变 markdown 结构（mermaid 标签被劈断是实测过的）', () => {
  const md = rg.toMarkdown(hostileReport());
  const nodeLines = md.split(/\r?\n/).filter((l) => /^\s*S\d+\["/.test(l));
  const closed = nodeLines.filter((l) => /"\]$/.test(l));
  assert.equal(closed.length, nodeLines.length, `mermaid 节点标签被表名里的换行劈断：\n${nodeLines.join('\n')}`);
  // 围栏内不得出现「以公式前缀开头的裸行」（=HYPERLINK(...) 那一段必须被压进标签里）
  const inFence = md.split(/```mermaid\n/)[1]?.split('\n```')[0] || '';
  const loose = inFence.split(/\r?\n/).filter((l) => l && !/^(flowchart TD|\s*S\d+|=\s*>)/.test(l.trim()) && !/^\s*S\d+ /.test(l));
  const bad = inFence.split(/\r?\n/).filter((l) => /^[=+\-@]/.test(l.trim()));
  assert.deepEqual(bad, [], `mermaid 围栏内出现以公式前缀开头的裸行：\n${bad.join('\n')}`);
  assert.ok(loose.length === 0, `mermaid 围栏内有非节点行：\n${loose.join('\n')}`);
});

test('③b 攻击路径 markdown 段单独钉（mermaid 与编号清单两个出口）', () => {
  const lines = attackPathMarkdown(hostileReport());
  const bad = lines.filter((l) => RAW_TAG.test(l));
  assert.deepEqual(bad, [], `攻击路径段泄漏裸标签：\n${bad.join('\n')}`);
});

test('③c 「Payload 示例」小节的围栏同样由内容决定（历史上这里是手写反引号）', () => {
  const md = rg.toMarkdown(hostileReport());
  const sec = md.split('## Payload 示例')[1].split('\n##')[0];
  const line = sec.split(/\r?\n/).find((l) => l.startsWith('- '));
  assert.ok(line, 'Payload 示例行必须存在');
  assert.equal(line.replace(/(`+)[\s\S]*?\1/g, '').trim(), '-', 'payload 有半截落在代码位之外');
});

test('④ CSV 拖库区块：列头过公式守卫，区块标题行不得被表名拆出新单元格', () => {
  const csv = rg.toCSV(hostileReport());
  const dumpStart = csv.indexOf('# 拖库数据');
  assert.ok(dumpStart >= 0, '拖库区块必须存在（否则本守卫形同虚设）');
  const dump = csv.slice(dumpStart).split(/\r?\n/).filter(Boolean);
  const sectionLines = dump.filter((l) => l.startsWith('## '));
  assert.equal(sectionLines.length, 1, '表名里的换行不得凭空造出第二个区块标题');
  assert.ok(!sectionLines[0].includes(','), '区块标题行不得含逗号（后半段会变成一个独立单元格）');
  // 数据行（含列头）必须是「每个单元格都带引号」的合法 CSV 行
  const cellLines = dump.filter((l) => !l.startsWith('#'));
  assert.ok(cellLines.length >= 2, '至少应有列头行 + 数据行');
  for (const l of cellLines) {
    assert.match(l, /^"([^"]|"")*"(,("([^"]|"")*"))*$/, `未完全引用的 CSV 行：${l}`);
  }
  // 首个单元格不得以公式前缀开头（csvSafeCell 会加 ' 前缀，引号内则是 "" 形态）
  for (const l of cellLines) {
    const first = l.split('",')[0].replace(/^"/, '');
    assert.ok(!/^[=+\-@]/.test(first), `单元格以公式前缀开头：${first}`);
  }
});

test('⑤ isInternalHost：IPv6 字面量（含 URL 规范化后的十六进制形态）不得成为可点击链接', () => {
  const internal = [
    '::ffff:127.0.0.1',
    '::ffff:7f00:1', // whatwg-url 把上一条规范化成这个形态
    '::ffff:a00:5',
    '::7f00:1',
    '::127.0.0.1',
    '2002:7f00:1::', // 6to4 内嵌原 v4
    'fd00::1', // ULA
    'fe80::1', // 链路本地
    '::',
  ];
  for (const h of internal) assert.equal(isInternalHost(`[${h}]`), true, `${h} 应判内网`);
  const external = ['2001:db8::1', '8.8.8.8', 'shop.example.com', '192.0.200.5', '100.128.0.1', '172.32.0.1'];
  for (const h of external) assert.equal(isInternalHost(h), false, `${h} 是公网，不该被降级成纯文本`);
});

test('⑥ 同一份 hostile 报告多次导出逐字节一致（新增转义不得引入不稳定输出）', () => {
  const report = hostileReport(); // 必须复用同一个报告对象：generatedAt 走 WeakMap 缓存
  assert.equal(rg.toMarkdown(report), rg.toMarkdown(report));
  assert.equal(rg.toCSV(report), rg.toCSV(report));
});
