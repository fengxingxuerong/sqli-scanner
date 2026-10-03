// =====================================================================
// reportSections.js —— 报告的**章节渲染**（markdown / HTML 两侧共用一个模块）
//
// [大文件拆分 2026-10-03] 自 ReportGenerator.js 抽出（纯搬移 + 一处新增）。
// 抽出依据：这些函数**只依赖入参** `d`（buildDelivery 的产物）或 `report`，以及转义原语
// （HTML 侧的 `esc` 由调用方传入、markdown 侧的 `mdText/mdCell` 来自 reportHtml.js）。
// 它们此前是 ReportGenerator 的私有方法，却在方法体里从不读 `this` 的其它状态 ——
// 即「用 `this` 伪装成了有状态」，搬成自由函数后依赖方向变成单向，可独立测试。
//
// 依赖方向（无环）：
//   reportHtml.js（叶子） ← reportSections.js ← ReportGenerator.js
//
// 新增：`credentialRiskMarkdown/Html`（--passwords 的哈希识别与风险标注落进交付物）。
// =====================================================================
import { mdText, mdCell } from './reportHtml.js';
import { STRENGTH_LABEL } from '../engine/extraction/hashAnalysis.js';

// ============================================================================
// 结论可信度 / 抑制项 / 跳过点
// ============================================================================

/**
 * 结论可信度与「本次被抑制的能力」。
 * 交付物首屏必须说清两件事：
 *   ① 0 漏洞到底是「没测出」还是「没测成」（verdict/verdictNote 来自 scanValidityGuard）；
 *   ② 哪些能力被安全护栏压住了（summary.constraints）——否则「已按最高风险等级测试」是不实陈述。
 * 缺省（旧报告无这两个字段）时返回 null，整段不渲染（向后兼容）。
 * @param {any} report
 * @returns {{verdict:string, note:string, constraints:string[], skipped:{total:number,byReason:Record<string,number>}|null}|null}
 */
export function conclusion(report) {
  const s = (report && report.summary) || {};
  const verdict = String(s.verdict || '');
  const note = String(s.verdictNote || '');
  const constraints = Array.isArray(s.constraints)
    ? s.constraints.filter((x) => typeof x === 'string' && x.trim())
    : [];
  // [实战分析 P0-2 2026-10-02] 跳过点汇总进交付叙事：skippedPoints 此前只有 JSON 整包与
  // 前端逐点标注可见，导出的 md/HTML/SARIF 里「有多少点没测、为什么没测」不可见——
  // 甲方验收追问「测全了吗」时对外格式答不上。skipped = { total, byReason }
  // （scanHelpers.summarizeSkipped 产出；旧报告无此字段时整段照旧，向后兼容）。
  const sp = s.skippedPoints;
  const skipped =
    sp && Number.isFinite(sp.total) && sp.total > 0 && sp.byReason && typeof sp.byReason === 'object'
      ? { total: sp.total, byReason: sp.byReason }
      : null;
  if (!verdict && !note && !constraints.length && !skipped) return null;
  return { verdict, note, constraints, skipped };
}

/**
 * 跳过点的一行人话摘要（md/html 共用取数，防两处口径漂移）。
 * 原因码 → 现场语义：prefilter=预筛选、static=静态资源、input_validation=输入校验、
 * user-skip=用户指定跳过；未知原因码原样透出（新增原因码不被静默吞掉）。
 * @param {{total:number,byReason:Record<string,number>}|null} skipped
 * @returns {string|null}
 */
export function skippedText(skipped) {
  if (!skipped) return null;
  const LABEL = {
    prefilter: '预筛选（探针无信号）',
    static: '静态资源',
    input_validation: '输入校验（参数在进 SQL 前被拦死）',
    'user-skip': '用户指定跳过',
  };
  const parts = Object.entries(skipped.byReason)
    .filter(([, n]) => Number.isFinite(n) && n > 0)
    .map(([k, n]) => `${LABEL[k] || k} ${n}`);
  if (!parts.length) return null;
  return `跳过的注入点：**${skipped.total}** 个（${parts.join('、')}）——这些点**未被测试**，不计入「未检出」结论。`;
}

/** markdown：结论可信度 + 本次抑制项（返回行数组，空结论返回 []） */
export function conclusionMarkdown(report) {
  const c = conclusion(report);
  if (!c) return [];
  // [P1-FIX 2026-09-12] 有命中时不得原样展示 verdict：verdict 只描述「未检出」类阴性结论的
  // 可信度，与「已检出 N 条漏洞」并列会被读成自相矛盾——实测交付报告第一行出现
  // 「结论判定：no_vulnerability_detected」，而紧接着下方列着 3 条漏洞，属交付物级误导。
  const hits = Array.isArray(report?.vulns) ? report.vulns.length : 0;
  const out = [hits ? '## 本次命中与抑制项' : '## 结论可信度与本次抑制项', ''];
  if (hits) {
    out.push(
      `- 本次已检出 **${hits}** 条漏洞（详见下方清单）；verdict 仅用于描述「未检出」类阴性结论的可信度，不适用于本次结果。`
    );
  } else if (c.verdict) {
    out.push(`- 结论判定：**${c.verdict === 'inconclusive' ? '不可判定（inconclusive）' : c.verdict}**`);
  }
  if (c.note) out.push(`> ${c.note.replace(/\s*\n\s*/g, ' ')}`);
  // [实战分析 P0-2 2026-10-02] 跳过点统计进交付叙事（与抑制项并列：都回答「没测的部分」）
  const skippedLine = skippedText(c.skipped);
  if (skippedLine) out.push(`- ${skippedLine}`);
  if (c.constraints.length) {
    out.push('', '- 本次被抑制的能力（不代表已测试）：');
    for (const x of c.constraints) out.push(`  - ${x}`);
  }
  out.push('');
  return out;
}

/** HTML：结论可信度 + 抑制项（无结论返回空串） */
export function conclusionHtml(report, esc) {
  const c = conclusion(report);
  if (!c) return '';
  const items = c.constraints.map((x) => `<li>${esc(x)}</li>`).join('');
  const bad = c.verdict === 'inconclusive';
  // [P1-FIX 2026-09-12] 与 conclusionMarkdown 同源：有命中时不展示 verdict（语义冲突会误导）
  const hits = Array.isArray(report?.vulns) ? report.vulns.length : 0;
  const title = hits ? '本次命中与抑制项' : bad ? '结论不可信：未检出 ≠ 无漏洞' : '结论可信度与本次抑制项';
  const verdictLine = hits
    ? `<p class="meta">本次已检出 ${hits} 条漏洞；verdict 仅描述「未检出」类阴性结论的可信度，不适用于本次结果。</p>`
    : c.verdict
      ? `<p class="meta">判定：${esc(c.verdict)}</p>`
      : '';
  return `<div class="verdict${bad && !hits ? ' bad' : ''}">
      <h2>${title}</h2>
      ${verdictLine}
      ${c.note ? `<p>${esc(c.note)}</p>` : ''}
      ${(() => {
        // [实战分析 P0-2 2026-10-02] 与 conclusionMarkdown 同源：跳过点统计进交付叙事
        // （先转义再去掉 markdown 加粗标记 —— 原因码虽是引擎字面量，出口消毒不设例外）
        const line = skippedText(c.skipped);
        return line ? `<p class="meta">${esc(line).replace(/\*\*/g, '')}</p>` : '';
      })()}
      ${items ? `<p class="meta">本次被抑制的能力（不代表已测试）：</p><ul>${items}</ul>` : ''}
    </div>`;
}

// ============================================================================
// [2026-09-13] 交付层章节（markdown/html 共用取数源 buildDelivery；只增小节不改既有行）
// ============================================================================

/** markdown 报告元信息 */
export function metaMarkdown(d) {
  const out = ['', '## 报告元信息', ''];
  out.push(`- 起止时间：${d.meta.startedAt || '-'} → ${d.meta.finishedAt || '-'}（耗时 ${d.meta.durationText || '-'}）`);
  out.push(`- 请求总数：${d.meta.requestCount ?? '-'} · 检测配置：level=${d.meta.level ?? '-'} · risk=${d.meta.risk ?? '-'} · 技术=${d.meta.techniques || '-'}`);
  out.push(`- 测试范围：${d.meta.scope}`);
  out.push('- 授权声明：本报告仅供授权安全测试使用；未获授权对任何系统进行扫描、测试或数据提取均可能违反法律法规。');
  out.push(`- 生成时间：${d.meta.generatedAt}`, '');
  return out;
}

/** markdown 执行摘要（管理层视角：结果 + 影响实证 + 可信度 + 定库依据） */
export function execMarkdown(d) {
  const e = d.exec;
  const out = ['', '## 执行摘要', ''];
  if (e.vulnCount) {
    const techs = e.techniques.join('/') || '-';
    out.push(`- 目标 ${d.meta.target} 共测试 ${e.pointCount} 个注入点，检出 **${e.vulnCount}** 条 SQL 注入漏洞（技术：${techs}），最高风险 **${e.riskLevel}**${e.dbms ? `，数据库 ${e.dbms}` : ''}。`);
    if (e.impact) {
      out.push(`- **影响实证**：本次已提取 ${e.impact.tableCount} 张表 / ${e.impact.rowCount} 行数据（样例：${e.impact.sampleTables.join('、')}），数据泄露风险已被验证成立。`);
    } else {
      out.push('- 影响实证：本次未开启拖库（enableExtract），影响面按检出通道定性推断（union/error 通道通常可达数据读出）。');
    }
  } else {
    out.push(`- 目标 ${d.meta.target} 共测试 ${e.pointCount} 个注入点，**未检出漏洞**。`);
  }
  if (e.validity) {
    out.push(`- 结论可信度：${e.validity.status}${e.validity.reliable === false ? '（**结论不可信，见「结论可信度」小节**）' : ''}${e.validity.reason ? `——${e.validity.reason}` : ''}。`);
  }
  if (e.dbmsEvidence) {
    out.push(`- 定库依据：${e.dbmsEvidence.levelText || e.dbmsEvidence.level || '-'}（${e.dbmsEvidence.dbms || '-'}）${e.dbmsEvidence.caveat ? `；${e.dbmsEvidence.caveat}` : ''}。`);
  }
  out.push('');
  return out;
}

/** markdown 修复建议（按注入点 + 通用基线） */
export function remediationMarkdown(d) {
  const out = ['', '## 修复建议（Remediation）', ''];
  if (d.remediation.perVuln.length) {
    out.push('### 按注入点', '');
    for (const it of d.remediation.perVuln) {
      // [2026-09-17] 标题带受影响参数：整改清单必须能对应到具体参数，不能只有内部 pointId hash
      // [2026-09-24] affectedParam 是**目标可控**的参数名 → 正文位必须过 mdText（同 mdCell）
      const where = it.affectedParam ? ` · ${mdText(it.affectedParam)}` : '';
      out.push(`**${it.pointId}${where} · ${it.technique} · CVSS ${it.cvss.score} ${it.cvss.severity}**（\`${it.cvss.vector}\`）`, '');
      for (const a of it.actions) out.push(`- ${a}`);
      out.push('');
    }
  } else {
    out.push('未检出漏洞，以下为通用加固基线。', '');
  }
  out.push('### 通用加固基线', '');
  for (const a of d.remediation.general) out.push(`- ${a}`);
  out.push('');
  out.push('> CVSS 口径：v3.1 启发式映射（按技术通道给分，环境项未设），供排期排序参考，非逐条人工评定。', '');
  return out;
}

/** markdown WAF 交战记录 */
export function wafMarkdown(d) {
  const w = d.waf;
  const out = ['', '## WAF 交战记录', ''];
  if (!w.engaged) {
    out.push('- 本次未观察到 WAF 拦截或厂商特征（activeWafProbe 默认关闭，未主动探测）。', '');
    return out;
  }
  if (w.detected.length) {
    out.push(`- 识别到 WAF 厂商：${w.detected.map((v) => `${v.vendor}（置信度 ${v.confidence ?? '-'}）`).join('、')}。`);
  }
  out.push(`- 被拦截请求数：${w.blockHits ?? '-'}。`);
  if (w.blockPolicy) {
    const hint = Array.isArray(w.blockPolicy.tamperHint) && w.blockPolicy.tamperHint.length ? `；自动换用 tamper：${w.blockPolicy.tamperHint.join(', ')}` : '';
    out.push(`- 处置策略：${w.blockPolicy.action}——${w.blockPolicy.reason || ''}${hint}。`);
  }
  out.push('');
  return out;
}

/** HTML 报告元信息 + 执行摘要（合并渲染在既有结论卡之前） */
export function deliveryHtml(d, esc) {
  const items = [
    `起止时间：${esc(d.meta.startedAt || '-')} → ${esc(d.meta.finishedAt || '-')}（耗时 ${esc(d.meta.durationText || '-')}）`,
    `请求总数：${esc(d.meta.requestCount ?? '-')} · 检测配置：level=${esc(d.meta.level ?? '-')} · risk=${esc(d.meta.risk ?? '-')} · 技术=${esc(d.meta.techniques || '-')}`,
    `测试范围：${esc(d.meta.scope)}`,
    '授权声明：本报告仅供授权安全测试使用；未获授权对任何系统进行扫描、测试或数据提取均可能违反法律法规。',
    `生成时间：${esc(d.meta.generatedAt)}`,
  ]
    .map((x) => `<li>${x}</li>`)
    .join('');
  const e = d.exec;
  const execLines = [];
  if (e.vulnCount) {
    const techs = esc(e.techniques.join('/') || '-');
    execLines.push(`目标 ${esc(d.meta.target)} 共测试 ${e.pointCount} 个注入点，检出 <b>${e.vulnCount}</b> 条 SQL 注入漏洞（技术：${techs}），最高风险 <b>${esc(e.riskLevel)}</b>${e.dbms ? `，数据库 ${esc(e.dbms)}` : ''}。`);
    execLines.push(
      e.impact
        ? `影响实证：本次已提取 ${e.impact.tableCount} 张表 / ${e.impact.rowCount} 行数据（样例：${esc(e.impact.sampleTables.join('、'))}），数据泄露风险已被验证成立。`
        : '影响实证：本次未开启拖库（enableExtract），影响面按检出通道定性推断。'
    );
  } else {
    execLines.push(`目标 ${esc(d.meta.target)} 共测试 ${e.pointCount} 个注入点，<b>未检出漏洞</b>。`);
  }
  if (e.validity) execLines.push(`结论可信度：${esc(e.validity.status)}${e.validity.reason ? `——${esc(e.validity.reason)}` : ''}。`);
  if (e.dbmsEvidence) execLines.push(`定库依据：${esc(e.dbmsEvidence.levelText || e.dbmsEvidence.level || '-')}（${esc(e.dbmsEvidence.dbms || '-')}）。`);
  return `<div class="verdict">
        <h2>报告元信息</h2>
        <ul class="meta">${items}</ul>
        <h2>执行摘要</h2>
        ${execLines.map((x) => `<p>${x}</p>`).join('\n        ')}
      </div>`;
}

/** HTML 修复建议 */
export function remediationHtml(d, esc) {
  const per = d.remediation.perVuln
    .map((it) => {
      const actions = it.actions.map((a) => `<li>${esc(a)}</li>`).join('');
      // [2026-09-17] 标题带受影响参数（与 markdown 侧同口径）
      const where = it.affectedParam ? ` · ${esc(it.affectedParam)}` : '';
      return `<div class="poc"><p><b>${esc(it.pointId)}</b>${where}<b> · ${esc(it.technique)}</b> · CVSS ${esc(it.cvss.score)} ${esc(it.cvss.severity)}（<code>${esc(it.cvss.vector)}</code>）</p><ul>${actions}</ul></div>`;
    })
    .join('');
  const general = d.remediation.general.map((a) => `<li>${esc(a)}</li>`).join('');
  return `<h2>修复建议（Remediation）</h2>
      ${per || '<p class="meta">未检出漏洞，以下为通用加固基线。</p>'}
      <p class="meta"><b>通用加固基线</b></p><ul>${general}</ul>
      <p class="meta">CVSS 口径：v3.1 启发式映射（按技术通道给分，环境项未设），供排期排序参考，非逐条人工评定。</p>`;
}

/** HTML WAF 交战记录 */
export function wafHtml(d, esc) {
  const w = d.waf;
  if (!w.engaged) {
    return '<h2>WAF 交战记录</h2><p class="meta">本次未观察到 WAF 拦截或厂商特征（activeWafProbe 默认关闭，未主动探测）。</p>';
  }
  const vendorLine = w.detected.length
    ? `<p>识别到 WAF 厂商：${esc(w.detected.map((v) => `${v.vendor}（置信度 ${v.confidence ?? '-'}）`).join('、'))}。</p>`
    : '';
  const policy = w.blockPolicy
    ? `<p>处置策略：${esc(w.blockPolicy.action)}——${esc(w.blockPolicy.reason || '')}${
        Array.isArray(w.blockPolicy.tamperHint) && w.blockPolicy.tamperHint.length
          ? `；自动换用 tamper：${esc(w.blockPolicy.tamperHint.join(', '))}`
          : ''
      }。</p>`
    : '';
  return `<h2>WAF 交战记录</h2><p class="meta">${vendorLine}被拦截请求数：${esc(w.blockHits ?? '-')}。</p>${policy}`;
}

// ============================================================================
// [--passwords 升级] 凭据风险章节
// ============================================================================
// 数据来自 `engine/extraction/hashAnalysis.js` 的 `analyzePasswords`（见 report.data.passwordAnalysis）。
// 两条纪律：
//   ① **账号名/主机名是目标可控输入** → markdown 走 mdCell、HTML 走 esc（与参数名同等待遇）。
//   ② 只渲染「需要整改」的条目（空口令 / 弱哈希 / 未识别），且**不回显原始哈希** ——
//      报告常在客户之间流转，这一节不该成为凭据的第二份副本。

/** 每节最多列出的账号条目数（超出给指针，不静默截断） */
const CRED_TABLE_LIMIT = 20;

/** 需要优先整改的条目（空/弱/未识别） */
function riskyCredentialEntries(analysis) {
  return (analysis.entries || []).filter((e) => e.risk === 'high' || e.risk === 'unknown');
}

/** 一行统计摘要（md/html 共用文案，避免两处口径漂移） */
function credentialSummaryLine(a) {
  const parts = [`未设口令/非口令插件 ${a.blank}`, `弱 ${a.weak}`, `中 ${a.medium}`, `强 ${a.strong}`];
  if (a.unknown) parts.push(`未识别 ${a.unknown}`);
  return `解析到 ${a.total} 个账号的凭据：${parts.join(' · ')}。`;
}

const CRED_CAVEAT =
  '判定口径：仅按**哈希格式**识别算法，离线完成，**未做任何爆破、未联网**。' +
  '「未设口令/非口令插件」二者在 SQL 层不可区分（如 MySQL auth_socket 同样表现为空）。' +
  '「弱」指该 KDF 离线爆破成本低，**不代表口令已被还原**。';

/**
 * markdown：凭据风险小节（无分析结果返回 []，整段不渲染）
 * @param {any} analysis report.data.passwordAnalysis
 * @returns {string[]}
 */
export function credentialRiskMarkdown(analysis) {
  if (!analysis || !analysis.total) return [];
  const out = ['', '## 凭据风险（--passwords）', ''];
  out.push(`- ${credentialSummaryLine(analysis)}`);
  const algos = Object.entries(analysis.algorithms || {})
    .sort((a, b) => b[1] - a[1])
    .map(([k, n]) => `${k} × ${n}`);
  if (algos.length) out.push(`- 算法分布：${algos.join('、')}。`);
  const risky = riskyCredentialEntries(analysis);
  if (risky.length) {
    out.push('', '| 账号 | 主机 | 算法 | 强度 | 风险 |', '|---|---|---|---|---|');
    for (const e of risky.slice(0, CRED_TABLE_LIMIT)) {
      out.push(
        `| ${mdCell(e.user)} | ${mdCell(e.host ?? '-')} | ${mdCell(e.label)} | ${mdCell(STRENGTH_LABEL[e.strength] || e.strength)} | ${mdCell(e.risk)} |`
      );
    }
    if (risky.length > CRED_TABLE_LIMIT) {
      out.push('', `> 其余 ${risky.length - CRED_TABLE_LIMIT} 条同类条目未在此展开，完整清单见 report.json 的 \`data.passwordAnalysis.entries\`。`);
    }
  } else {
    out.push('', '- 未发现空口令 / 弱哈希 / 未识别格式。');
  }
  out.push('', `> ${CRED_CAVEAT} 本节**不回显原始哈希**（原始串见 report.json 的 \`data.passwords\`）。`, '');
  return out;
}

/**
 * HTML：凭据风险卡（无分析结果返回空串）
 * @param {any} analysis report.data.passwordAnalysis
 * @param {(s: unknown) => string} esc HTML 转义原语
 * @returns {string}
 */
export function credentialRiskHtml(analysis, esc) {
  if (!analysis || !analysis.total) return '';
  const risky = riskyCredentialEntries(analysis);
  const rows = risky
    .slice(0, CRED_TABLE_LIMIT)
    .map(
      (e) =>
        `<tr><td>${esc(e.user)}</td><td>${esc(e.host ?? '-')}</td><td>${esc(e.label)}</td><td>${esc(STRENGTH_LABEL[e.strength] || e.strength)}</td><td class="${e.risk === 'high' ? 'high' : 'medium'}">${esc(e.risk)}</td></tr>`
    )
    .join('');
  const table = rows
    ? `<table><thead><tr><th>账号</th><th>主机</th><th>算法</th><th>强度</th><th>风险</th></tr></thead><tbody>${rows}</tbody></table>`
    : '<p class="meta">未发现空口令 / 弱哈希 / 未识别格式。</p>';
  const more =
    risky.length > CRED_TABLE_LIMIT
      ? `<p class="meta">其余 ${risky.length - CRED_TABLE_LIMIT} 条同类条目未在此展开，完整清单见 report.json 的 <code>data.passwordAnalysis.entries</code>。</p>`
      : '';
  const algoLine = Object.entries(analysis.algorithms || {})
    .sort((a, b) => b[1] - a[1])
    .map(([k, n]) => `${k} × ${n}`)
    .join('、');
  return `<div class="verdict${analysis.blank || analysis.weak ? ' bad' : ''}">
      <h2>凭据风险（--passwords）</h2>
      <p class="meta">${esc(credentialSummaryLine(analysis))}</p>
      ${algoLine ? `<p class="meta">算法分布：${esc(algoLine)}。</p>` : ''}
      ${table}
      ${more}
      <p class="meta">${esc(CRED_CAVEAT)}。本节不回显原始哈希（原始串见 report.json 的 <code>data.passwords</code>）。</p>
    </div>`;
}
