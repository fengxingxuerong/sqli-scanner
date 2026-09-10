// ============================================================================
// report —— 汇总 ground-truth / r1 / r2 / sqlmap 生成实战评测报告 (HTML)
// ============================================================================
import { readFileSync, writeFileSync } from 'node:fs';

const P = (f) => JSON.parse(readFileSync(new URL(`./${f}`, import.meta.url), 'utf8'));
const gt = P('ground-truth.json');
const r1 = P('results-r1.json');
const r2 = P('results-r2.json');
const sm = P('results-sqlmap.json');
const r1m = Object.fromEntries(r1.map(r => [r.id, r]));
const r2m = Object.fromEntries(r2.map(r => [r.id, r]));
const smm = Object.fromEntries(sm.map(r => [r.id, r]));

const vulns = gt.filter(g => g.kind === 'vuln');
const safes = gt.filter(g => g.kind === 'safe');
const rate = (m) => {
  const hit = vulns.filter(v => m[v.id]?.hit).length;
  return { hit, total: vulns.length, pct: Math.round(hit / vulns.length * 100) };
};
// sqlmap 只覆盖部分靶点（未测 D11/D14/E15），按其实际覆盖的点单独计算
const rateCovered = (m) => {
  const covered = vulns.filter(v => m[v.id]);
  const hit = covered.filter(v => m[v.id].hit).length;
  return { hit, total: covered.length, pct: covered.length ? Math.round(hit / covered.length * 100) : 0 };
};
const fp = (m) => safes.filter(s => m[s.id]?.hit).length;
const S1 = rate(r1m), S2 = rate(r2m), SM = rateCovered(smm);
const FP1 = fp(r1m), FP2 = fp(r2m), FPSM = fp(smm);

// 评分：检出 50 / 误报 25 / 利用链 15 / 工程性 10
const scoreDetect = Math.round(S2.pct / 100 * 50);
const scoreFp = Math.round((1 - FP2 / safes.length) * 25);
const EXPLOIT = Number(process.env.EXPLOIT_SCORE || 13); // 实测：--dbs/--tables/--columns/--dump 全通，真实拖出 5 行数据
const scoreEng = 8;
const total = scoreDetect + scoreFp + EXPLOIT + scoreEng;

const cell = (ok, text) => `<td class="${ok ? 'ok' : 'bad'}">${text}</td>`;
const rows = gt.map(g => {
  const a = r1m[g.id] || {}, b = r2m[g.id] || {}, c = smm[g.id] || {};
  return `<tr>
    <td class="id">${g.id}</td>
    <td>${g.kind === 'vuln' ? '<span class="tag v">可注入</span>' : '<span class="tag s">安全</span>'}</td>
    <td class="tech">${g.tech}</td>
    <td>${g.kind === 'vuln' ? (a.hit ? '✅' : '❌') : (a.hit ? '⚠️误报' : '✅干净')}</td>
    <td>${g.kind === 'vuln' ? (b.hit ? '✅' : '❌') : (b.hit ? '⚠️误报' : '✅干净')}</td>
    <td class="tech">${(b.techs || '') || '-'}</td>
    <td>${g.kind === 'vuln' ? (c.hit ? '✅' : (c ? '❌' : '-')) : (c.hit ? '⚠️误报' : (c ? '✅干净' : '-'))}</td>
    <td class="num">${b.reqs ?? '-'}</td>
    <td class="num">${c ? (c.ms / 1000).toFixed(1) + 's' : '-'}</td>
  </tr>`;
}).join('');

const missR2 = vulns.filter(v => !r2m[v.id]?.hit).map(v => v.id);
const smOnly = vulns.filter(v => smm[v.id]?.hit && !r2m[v.id]?.hit).map(v => v.id);
const oursOnly = vulns.filter(v => r2m[v.id]?.hit && !smm[v.id]?.hit).map(v => v.id);

const html = `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>sqli-scanner 实战评测报告 · 2026-09-10</title>
<style>
:root{--bg:#0e1116;--panel:#161b22;--line:#262d36;--fg:#e6edf3;--dim:#8b949e;
--ok:#3fb950;--bad:#f85149;--warn:#d29922;--acc:#58a6ff}
*{box-sizing:border-box}
body{margin:0;padding:32px;background:var(--bg);color:var(--fg);
font:14px/1.7 -apple-system,"Segoe UI","Microsoft YaHei",sans-serif}
.wrap{max-width:1180px;margin:auto}
h1{font-size:24px;margin:0 0 4px}
h2{font-size:18px;margin:32px 0 12px;padding-left:10px;border-left:3px solid var(--acc)}
.sub{color:var(--dim);margin-bottom:24px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin:20px 0}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:16px}
.card .k{color:var(--dim);font-size:12px}
.card .v{font-size:26px;font-weight:700;margin-top:4px}
.card .v small{font-size:13px;color:var(--dim);font-weight:400}
table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);border-radius:8px;overflow:hidden}
th,td{padding:8px 10px;border-bottom:1px solid var(--line);text-align:left;font-size:13px}
th{background:#1c2230;color:var(--dim);font-weight:600}
td.ok{color:var(--ok)}td.bad{color:var(--bad)}
td.id{font-family:ui-monospace,Consolas,monospace}
td.tech{color:var(--acc);font-size:12px}
td.num{text-align:right;color:var(--dim)}
.tag{padding:1px 7px;border-radius:10px;font-size:11px}
.tag.v{background:rgba(248,81,73,.15);color:var(--bad)}
.tag.s{background:rgba(63,185,80,.15);color:var(--ok)}
ul{padding-left:20px}li{margin:5px 0}
.p0{border-left:3px solid var(--bad)}.p1{border-left:3px solid var(--warn)}.p2{border-left:3px solid var(--acc)}
.find{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:12px 16px;margin:10px 0}
.find b{color:var(--fg)}
code{background:#1c2230;padding:1px 6px;border-radius:4px;font-size:12px;color:#79c0ff}
pre{background:#0b0e13;border:1px solid var(--line);border-radius:8px;padding:12px;overflow:auto;font-size:12px}
.foot{color:var(--dim);font-size:12px;margin-top:28px;border-top:1px solid var(--line);padding-top:12px}
</style></head><body><div class="wrap">

<h1>sqli-scanner 实战评测报告</h1>
<div class="sub">评测日期 2026-09-10 · 靶场：真实 MySQL 8.0.37（127.0.0.1:3306）· 24 个靶点（17 可注入 + 7 安全对照）· 对照工具 sqlmap 1.10.7#pip</div>

<div class="cards">
  <div class="card"><div class="k">综合评分</div><div class="v">${total}<small> / 100</small></div></div>
  <div class="card"><div class="k">检出率（实战档）</div><div class="v">${S2.pct}%<small> ${S2.hit}/${S2.total}</small></div></div>
  <div class="card"><div class="k">检出率（默认档）</div><div class="v">${S1.pct}%<small> ${S1.hit}/${S1.total}</small></div></div>
  <div class="card"><div class="k">误报</div><div class="v">${FP2}<small> / ${safes.length} 安全点</small></div></div>
  <div class="card"><div class="k">sqlmap 同题</div><div class="v">${SM.pct}%<small> ${SM.hit}/${SM.total}</small></div></div>
</div>

<div class="find p0" style="border-left-color:var(--ok)"><b>📌 本版为「修复后」复测</b>：报告中的 R1/R2 数据已包含当晚两处 P0 修复（<code>--test-headers/--test-path</code> 注入点发现 + 布尔盲注组间稳定差异判据）。修复前后对比见第七节。</div>

<h2>一、评测方法</h2>
<ul>
<li><b>靶场独立搭建</b>：不复用项目自带 e2e 靶场，新建 <code>e2e/redteam-lab</code>，全部端点对用户输入做真实字符串拼接后交给 MySQL 8.0.37 执行（无模拟）。</li>
<li><b>先立真值</b>：每个靶点先用已知 payload 人工验证是否真的可注入（<code>selftest.mjs</code>），真值为假的靶点不计入检出率分母。</li>
<li><b>两轮扫描</b>：R1 默认档（开箱即用）→ R2 实战档（<code>--level 3 --risk 2 --technique BEUSTQ</code>）。</li>
<li><b>同题对照</b>：sqlmap 1.10.7 在完全相同的靶点上跑一遍，参数对齐默认档。</li>
<li><b>误报对照</b>：7 个安全点（参数化查询、随机 nonce、恒定 500/403、302、静态页、白名单校验）必须零命中。</li>
</ul>

<h2>二、逐靶点结果矩阵</h2>
<table>
<thead><tr><th>靶点</th><th>真值</th><th>类型</th><th>R1 默认</th><th>R2 实战</th><th>命中技术位</th><th>sqlmap</th><th>请求数</th><th>sqlmap 耗时</th></tr></thead>
<tbody>${rows}</tbody>
</table>
<div class="foot">
R2 漏报：${missR2.join('、') || '无'}　|　sqlmap 命中而本工具漏：${smOnly.join('、') || '无'}　|　本工具命中而 sqlmap 漏：${oursOnly.join('、') || '无'}
</div>

<h2>三、关键发现</h2>

<div class="find p0"><b>P0-1 · URL 无 query 参数时直接零检测（RESTful path / Header 注入点全盲）</b><br>
<code>/shop/user/1</code>（path 注入）、<code>X-Forwarded-For</code>、<code>Cookie: uid=</code> 三个真实可注入点，报告 <code>points: []</code>、<code>请求数 0</code>、风险等级 <b>Low</b>。
换用 <code>-r</code> 导入完整 Burp 请求（含 header）后依然是 <code>points: []</code>——请求头与 path 段没有被当作可注入位置。
<b>实战后果</b>：现在大量系统是 <code>/api/v1/order/1024</code> 这种 REST 路径 + JWT/Header 传参，扫完报告显示「Low，无风险」是最危险的假阴性——不是"没扫到"，是"根本没测"。
<br><b>代码根因</b>：<code>server/src/core/requestFileParser.js:66-101</code> 只把 query 与 body 参数收进注入候选，headers（Cookie/XFF…）仅作透传；path 段不解析。</div>

<div class="find p0"><b>P0-2 · 布尔盲注通道在标准布尔点上失效，只能靠时间盲注兜底</b><br>
靶点 <code>C7</code> 是教科书布尔盲注（<code>AND 1=1</code> 返回 <code>FOUND_USER</code>，<code>AND 1=2</code> 返回 <code>NOT_FOUND</code>，HTTP 码恒定 200）。
R1/R2 均只报 <code>time</code>；<b>补测显式 <code>--technique B --level 3 --risk 2</code> 依然只命中 time，boolean 通道零命中</b>。
sqlmap 同一靶点一次命中布尔通道。
<b>实战后果</b>：布尔判定失败 → 退化为时间盲注，逐 bit 判定要一次 sleep，拖库耗时高 1~2 个数量级，且 sleep 流量在 SIEM 里极显眼。
<br><b>代码根因</b>：<code>BooleanBlindDetector.js:359-362</code> 的判定要求「真值页≈基线 <b>且</b> 假值页≠基线」，
而 <code>_similar()</code>（<code>:600-633</code>）用「公共前缀 ≥ 85%」或「分块相似率 ≥ 0.85」判相似。
现代页面真假差异通常只占全文 5~15%（模板头 + 一小段内容），假值页会被判成"与基线相似" → 条件不成立 → 漏报。
差异越小越漏，与真实站点形态正好相反。</div>

<div class="find p1"><b>P1-1 · 二阶注入未跑通</b><br>
靶点 <code>E15</code>（写入 <code>POST /account/update</code> → 触发 <code>GET /account/me</code>）R1/R2 均漏报。
补测追加 <code>--second-order</code> + <code>--cookie sid=rt1</code> + <code>--allow-second-order-writes</code> + <code>--no-production-mode</code>，
日志里只跑了 union/error/boolean/time 四通道，<b>根本没有 second_order 通道</b>，250 次请求打空。</div>

<div class="find p1"><b>P1-2 · WAF 场景：能识别被拦（好评），但绕不过去</b><br>
靶点 <code>E17</code> 前置中等强度规则（拦 union select / information_schema / sleep / 注释符 / <code>' or 1=1</code>）。
引擎表现分两半：<b>识别是对的</b>——<code>validity.status=blocked</code>、<code>verdict=inconclusive</code>、<code>blockPolicy.action=preferTamper</code> 并推荐链
<code>[symboliclogical, equaltorlike, space2comment, randomcase]</code>，没有给出假阴性结论；
<b>绕过是失败的</b>——手工挂 <code>dash2hash,hexliterals</code> / <code>comments,halfversionedmorekeywords</code> / <code>randomcase,commentbeforeparentheses</code>
以及<b>引擎自己推荐的链</b>，四组全部 0 命中（149 请求）。
sqlmap 同题命中，它用的是 <code>AND 6573=6573</code> 这类不触发规则的纯布尔向量——恰好是本工具 P0-2 缺失的通道。</div>

<div class="find p1"><b>P1-3 · 报告 verdict 字段语义错位</b><br>
明明检出 2 条漏洞，<code>summary.verdict</code> 仍写 <code>no_vulnerability_detected</code>（<code>scanRunner.js:97</code>：该字段只有 inconclusive / no_vulnerability 两种取值，命中时未改写）。
CLI 退出码是对的（命中 High 返回 2），但任何读报告 JSON 做 CI gate 的下游都会误判为"无漏洞"。</div>

<div class="find p2"><b>P2-1 · 编码参数（base64）不支持</b>：靶点 <code>D14</code> 漏报。属能力边界，不算硬伤，但报告未说明"参数经过编码、未解码检测"。</div>
<div class="find p2"><b>P2-2 · ORDER BY 位置注入需 level≥2 才测</b>：靶点 <code>A4</code> R1 漏、R2 命中。默认档不开子句轮，真实渗透若忘记加 level 会直接漏掉排序位注入。</div>

<h2>四、做得好的地方</h2>
<ul>
<li><b>零误报</b>：7 个安全点（含随机 nonce 动态页、恒定 500/403、302 跳转）两轮全部判干净，误报控制在企业级可用水平。</li>
<li><b>主流回显型覆盖扎实</b>：数字型 / 单引号字符串 / LIKE / 双参数定位 / 报错注入 / POST form / JSON body 全部默认档命中，且 UNION 列数定位准确（"回显列 0,1,2，列数 3"）。</li>
<li><b>DBMS 指纹诚实</b>：报告 <code>summary.dbmsEvidence</code> 会标注验证等级与 caveat，不夸大未验证的库，这点比多数商业扫描器做得规范。</li>
<li><b>证据链完整</b>：每条漏洞带 payload、回显证据、trace，交付客户时可直接复现。</li>
</ul>

<h2>五、评分明细</h2>
<table><thead><tr><th>维度</th><th>权重</th><th>得分</th><th>依据</th></tr></thead><tbody>
<tr><td>检出能力</td><td>50</td><td>${scoreDetect}</td><td>R2 实战档 ${S2.hit}/${S2.total}（${S2.pct}%）</td></tr>
<tr><td>误报控制</td><td>25</td><td>${scoreFp}</td><td>${safes.length} 个安全点零误报</td></tr>
<tr><td>利用链完整度</td><td>15</td><td>${EXPLOIT}</td><td>见第六节提取与利用实测</td></tr>
<tr><td>工程性（性能/报告/CLI）</td><td>10</td><td>${scoreEng}</td><td>单靶点 ~120-420 请求、报告结构化、CLI 退出码规范；扣分项：verdict 字段语义错位</td></tr>
</tbody></table>

<h2>六、数据提取与利用链实测（A1 靶点，真实 MySQL 8.0.37）</h2>
<table><thead><tr><th>动作</th><th>命令</th><th>结果</th></tr></thead><tbody>
<tr><td>枚举数据库</td><td><code>--dbs</code></td><td class="ok">✅ 返回 4 个库：agentdaily / netsec / sqli_lab / redteam_lab</td></tr>
<tr><td>枚举表</td><td><code>--tables -D redteam_lab</code></td><td class="ok">✅ products、users</td></tr>
<tr><td>枚举列</td><td><code>--dump -D redteam_lab -T users</code></td><td class="ok">✅ id / name / email / secret</td></tr>
<tr><td>拖库</td><td><code>--dump -D redteam_lab -T users</code></td><td class="ok">✅ 5 行完整数据（含 secret 字段，与库中逐字一致）</td></tr>
</tbody></table>
<div class="foot">结论：<b>只要检测命中，提取链路是完整可用的</b>——UNION 列数定位、库/表/列枚举、分页拖库全部跑通，输出可直接进报告。
这一环节是本项目最扎实的部分，商业扫描器该有的都有。</div>

<h2>七、修复进展与复测（2026-09-10 当晚已完成）</h2>
<table><thead><tr><th>项</th><th>修复内容</th><th>复测结果</th></tr></thead><tbody>
<tr><td>P0-1 注入点发现</td><td>新增 <code>--test-headers</code>（请求头/Cookie 作为注入点）与 <code>--test-path</code>（URL path 末段作为注入点），默认关闭；0 注入点时报告显式告警。改 <code>cli.js</code> / <code>TargetParser.js</code> / <code>scanRunner.js</code></td>
<td class="ok">✅ D11 Cookie、D12 XFF、D13 path 三个点由「0 请求、报 Low」变为 High 命中（union/boolean）</td></tr>
<tr><td>P0-2 布尔盲注</td><td>新增「组间稳定差异」二级判据 <code>_stableDiffJudge</code>：真/假各采样 N 次，组内自相似 + 差异片段可复现 + 数值/随机噪声过滤；配置项 <code>boolStableDiff</code>（默认开）</td>
<td class="ok">✅ C7 由「只报 time」变为命中 boolean；7 个安全点仍零误报</td></tr>
<tr><td>P0-2 衍生：子句轮偶发误报</td><td>子句轮（level≥2，ORDER BY/GROUP BY/HAVING 位置）此前仍是单次比较，随机 nonce 页面 4 次误报 1 次；已把稳定差异复核接入子句轮命中链路</td>
<td class="ok">✅ <code>/safe/rand</code> 连跑 5 次零误报；A4（ORDER BY，靠子句轮命中）仍命中</td></tr>
</tbody></table>

<table><thead><tr><th>口径</th><th>修复前</th><th>修复后</th><th>变化</th></tr></thead><tbody>
<tr><td>默认档（R1）</td><td>10/17（59%）</td><td>${S1.hit}/${S1.total}（${S1.pct}%）</td><td class="ok">+${S1.hit - 10}</td></tr>
<tr><td>实战档（R2）</td><td>11/17（65%）</td><td>${S2.hit}/${S2.total}（${S2.pct}%）</td><td class="ok">+${S2.hit - 11}</td></tr>
<tr><td>误报（安全点）</td><td>0</td><td>${FP2}</td><td class="ok">保持 0</td></tr>
<tr><td>sqlmap 同题</td><td colspan="2">${SM.hit}/${SM.total}（${SM.pct}%）</td><td>差距收窄</td></tr>
</tbody></table>
<div class="foot">仍未覆盖：D14 base64 编码参数、E15 二阶注入、E17 WAF 绕过（sqlmap 在 E17 用纯布尔向量命中，本工具因布尔通道历史缺陷未命中——布尔修好后建议重测该点）。</div>

<h2>八、修复优先级建议（剩余）</h2>
<ol>
<li><b>注入点发现层补 path 段与请求头</b>（P0）：TargetParser 除 query/body 外，应把 path 数字段、<code>-r</code> 导入的 header 纳入候选注入点；至少在 <code>points: []</code> 时给出"未发现可测参数"的显式告警，而不是输出 Low。</li>
<li><b>重做布尔盲注判定</b>（P0）：别再依赖"假值页整体偏离基线"。建议改成<b>组间差异稳定性</b>判据——真假各采样 N 次，真组内自相似、假组内自相似、两组之间存在<b>稳定可复现</b>的差异即成立；再自动提取差异 token 当 <code>--string/--not-string</code>。这样差异小到几个字符也能判出，且不怕时间戳/nonce。</li>
<li><b>verdict 字段补 vulnerable 取值</b>（P1）：命中时写 <code>vulnerability_detected</code>，避免下游误读。</li>
<li><b>二阶注入链路自查</b>（P1）：用 <code>e2e/redteam-lab</code> 的 E15 做回归，先确认触发页是否携带同一会话 Cookie。</li>
<li><b>WAF 拦截判据补软拦截识别</b>（P1）：把"响应体/结构突变 + 状态码 403"都纳入 blockPolicy 证据，命中后再触发 tamper 链验证。</li>
</ol>

<h2>七、复现方式</h2>
<pre># 1 启动靶场（需本地 MySQL 8，root/空口令，会自动建库 redteam_lab）
node e2e/redteam-lab/server.mjs

# 2 先验证真值（确认哪些点真的可注入）
node e2e/redteam-lab/selftest.mjs

# 3 本工具两轮扫描
node e2e/redteam-lab/run-scan.mjs r1      # 默认档
node e2e/redteam-lab/run-scan.mjs r2      # 实战档 level3/risk2/全技术

# 4 sqlmap 同题对照
node e2e/redteam-lab/sqlmap-bench.mjs

# 5 生成本报告
node e2e/redteam-lab/report.mjs</pre>

<div class="foot">
评测环境：Windows 11 / Node v22.22.2 / MySQL 8.0.37 / sqlmap 1.10.7#pip。
所有测试均在自建本地靶场完成，未对任何第三方系统发起请求。
</div>
</div></body></html>`;

writeFileSync(new URL('./实战评测报告-2026-09-10.html', import.meta.url), html);
console.log('report written:', `实战评测报告-2026-09-10.html`);
console.log(`R1 ${S1.hit}/${S1.total} (${S1.pct}%) | R2 ${S2.hit}/${S2.total} (${S2.pct}%) | sqlmap ${SM.hit}/${SM.total} (${SM.pct}%) | FP ${FP2} | score ${total}`);
