// report.attackPath.test.js —— 攻击路径叙事的机械验证
// ============================================================================
// 三条主线：
//   ① **诚实边界**：层级只按报告里真实存在的证据推进，不虚构「已提权」
//   ② **自包含**：SVG 必须无外部依赖（报告是离线交付物，断网/CDN 挂了也要能看）
//   ③ **不可注入**：报告字段来自目标回显，必须转义（报告是 HTML 文件）
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  buildAttackPath,
  attackPathMarkdown,
  attackPathHtml,
  PATH_LEVELS,
} from '../src/services/reportAttackPath.js';

/** 最小可用 report 工厂 */
function makeReport(over = {}) {
  return {
    scanId: 's1',
    target: { url: 'https://t.example.com/list?id=1', method: 'GET', config: {} },
    points: [{ id: 'p1', param: 'id', location: 'query' }],
    vulns: [{ pointId: 'p1', technique: 'union', dbms: 'MySQL', riskLevel: 'High' }],
    data: null,
    ...over,
  };
}

test('空/畸形 report 不抛，且给出「未记录可利用路径」的结论（不谎报安全）', () => {
  for (const input of [undefined, null, {}, { vulns: null, points: 'x', data: 5 }]) {
    const p = buildAttackPath(input);
    assert.equal(p.level, PATH_LEVELS.NONE);
    assert.ok(p.stages.some((s) => s.kind === 'impact'), '即使无漏洞也要给影响结论段');
    assert.ok(p.note && p.note.length > 0, '必须带诚实边界说明');
    assert.ok(p.note.includes('不等于目标安全'), 'note 必须明确「未取得证据 ≠ 安全」');
  }
});

test('只有注入证据（无拖库数据）→ level=probe，且**不得**出现数据获取段（不虚构）', () => {
  const p = buildAttackPath(makeReport());
  assert.equal(p.level, PATH_LEVELS.PROBE);
  assert.deepEqual(p.reached, ['target', 'point', 'technique', 'impact']);
  assert.ok(!p.reached.includes('extraction'), '无 data.rows 时不得出现「数据获取」段 —— 那是虚构');
  assert.ok(p.note.includes('不代表目标仅到此为止'), 'probe 的 note 要说明扫描范围边界');
});

test('有拖库数据 → level=extract，出现数据获取段并给出表/行计数', () => {
  const p = buildAttackPath(makeReport({
    data: { rows: { 'app.users': [{ id: 1 }, { id: 2 }], 'app.orders': [{ id: 9 }] } },
  }));
  assert.equal(p.level, PATH_LEVELS.EXTRACT);
  const ex = p.stages.find((s) => s.kind === 'extraction');
  assert.ok(ex, '有数据时应出现数据获取段');
  assert.ok(ex.items[0].label.includes('2 张表'), `表数口径错：${ex.items[0].label}`);
  assert.ok(ex.items[0].label.includes('3 行'), `行数口径错：${ex.items[0].label}`);
  assert.ok(p.note.includes('未在本报告中执行或未留存证据'), 'extract 的 note 要划清利用链边界');
});

test('有堆叠注入证据 + 已读到数据 → level=exploit（高危利用证据存在）', () => {
  const p = buildAttackPath(makeReport({
    vulns: [
      { pointId: 'p1', technique: 'union', dbms: 'MySQL', riskLevel: 'High' },
      { pointId: 'p1', technique: 'stacked', dbms: 'MySQL', riskLevel: 'Critical' },
    ],
    data: { rows: { 'app.users': [{ id: 1 }] } },
  }));
  assert.equal(p.level, PATH_LEVELS.EXPLOIT);
  const impact = p.stages.find((s) => s.kind === 'impact');
  assert.ok(impact.items[0].detail.includes('堆叠'), 'exploit 段应点出堆叠证据');
});

test('层级单调：none < probe < extract < exploit（证据只会让层级递增）', () => {
  const order = [PATH_LEVELS.NONE, PATH_LEVELS.PROBE, PATH_LEVELS.EXTRACT, PATH_LEVELS.EXPLOIT];
  const seen = [
    buildAttackPath({}).level,
    buildAttackPath(makeReport()).level,
    buildAttackPath(makeReport({ data: { rows: { t: [{ a: 1 }] } } })).level,
    buildAttackPath(makeReport({
      vulns: [{ pointId: 'p1', technique: 'stacked', riskLevel: 'Critical' }],
      data: { rows: { t: [{ a: 1 }] } },
    })).level,
  ];
  for (let i = 1; i < seen.length; i++) {
    assert.ok(order.indexOf(seen[i]) >= order.indexOf(seen[i - 1]), `层级回退：${seen[i - 1]} → ${seen[i]}`);
  }
});

test('自包含：SVG **不得**含脚本标签或任何外部 URL 引用（断网/CDN 挂掉也要能看）', () => {
  const html = attackPathHtml(makeReport({ data: { rows: { t: [{ a: 1 }] } } }));
  assert.ok(html.includes('<svg'), '应输出内联 SVG');
  assert.ok(!/<script/i.test(html), 'SVG 段不得含 <script>（离线报告 + 无 XSS 面）');
  assert.ok(!/https?:\/\//i.test(html.replace(/https?:\/\/t\.example\.com/g, '')), '不得引用外部资源');
  assert.ok(!/xlink:href|url\(http/i.test(html), '不得引用外部 SVG 资源');
  // 也不得依赖 mermaid（它需要 CDN 的 JS）
  assert.ok(!/mermaid/i.test(html), 'HTML 侧不得依赖 mermaid');
});

test('不可注入：目标回显字段必须转义（报告是 HTML 文件）', () => {
  const evil = '<script>alert(1)</script>';
  const html = attackPathHtml(makeReport({
    points: [{ id: 'p1', param: evil, location: `query"><img src=x onerror=1` }],
    vulns: [{ pointId: 'p1', technique: `union"><svg onload=1`, dbms: evil, riskLevel: 'High' }],
    data: { rows: { [evil]: [{ a: 1 }] } },
  }));
  // ⚠️ 断言的是「危险结构」而不是「危险子串」：`onerror=1` 转义后仍会作为**文本**出现
  //    （`<` `>` `"` 已成实体，不再可执行）—— 首版断言 `!/onerror=1/` 因此假红，是断言写错不是实现出错。
  assert.ok(!/<script/i.test(html), 'param 未转义 → 报告可被注入脚本');
  assert.ok(!/<img/i.test(html), 'location 未转义 → 出现未转义的标签');
  assert.ok(!/<svg onload/i.test(html), 'technique 未转义');
  assert.ok(!/"><i/.test(html), '出现可闭合属性再起新标签的序列');
  // 反向确认「确实做了转义」：危险内容以实体形式出现。
  // ⚠️ 本仓共享的 `esc` 是**数字实体版**（`"` → `&#34;`、`'` → `&#39;`；`&<>` 用命名实体），
  //    断言写成 `&quot;` 会假红 —— 首版即踩此坑。
  assert.ok(
    html.includes('&lt;script&gt;') && html.includes('&#34;&gt;&lt;img'),
    '应以实体形式出现（注意 esc 是数字实体版）',
  );
});

test('markdown：mermaid 代码块 + 步骤列表双轨（渲染器不支持 mermaid 也不坏）', () => {
  const mdArr = attackPathMarkdown(makeReport({ data: { rows: { 'app.users': [{ a: 1 }] } } }));
  assert.ok(Array.isArray(mdArr), '返回行数组（与 pocMarkdown 契约一致）');
  const md = mdArr.join('\n');
  assert.ok(md.includes('```mermaid'), '应给 mermaid 代码块');
  assert.ok(md.includes('flowchart TD'));
  assert.ok(/^\d+\. \*\*入口\*\*/m.test(md), '应给人类可读的编号步骤');
  // mermaid 标签里的引号必须被替换，否则语法坏掉
  const evilMd = attackPathMarkdown(makeReport({
    vulns: [{ pointId: 'p1', technique: 'union"x"', dbms: 'MySQL', riskLevel: 'High' }],
  })).join('\n');
  const mermaidBlock = evilMd.split('```mermaid')[1].split('```')[0];
  assert.ok(!/\[".*".*"\]/.test(mermaidBlock), 'mermaid 标签内含未转义引号会导致语法错误');
});

test('超长字段被截断（SVG 不自动换行，溢出会盖住卡片）', () => {
  const long = 'A'.repeat(400);
  const p = buildAttackPath(makeReport({ points: [{ id: 'p1', param: long, location: 'query' }] }));
  const pointStage = p.stages.find((s) => s.kind === 'point');
  for (const it of pointStage.items) {
    assert.ok(it.label.length <= 60, `label 未截断：${it.label.length}`);
  }
});

test('DBMS 与授权范围被带进叙事（读者不必翻明细表反查）', () => {
  const p = buildAttackPath(makeReport({
    target: { url: 'https://t.example.com/a', method: 'POST', config: { scope: ['t.example.com'] } },
  }));
  assert.ok(p.stages[0].items[0].label.startsWith('POST '), '入口应带请求方法');
  assert.ok(p.stages[0].items[0].detail.includes('t.example.com'), '入口应带授权范围');
  assert.ok(p.stages.find((s) => s.kind === 'technique').items[0].detail.includes('MySQL'));
});
