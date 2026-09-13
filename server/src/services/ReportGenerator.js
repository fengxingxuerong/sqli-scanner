// ============================================================================
// patch/ReportGenerator.js —— 安全加固版报告生成器
// 基于 server/src/services/ReportGenerator.js 修改，修复项：
//   [P1-1] 导出前剥离 target 中的认证/代理等敏感配置（config.auth / cookieParams /
//          headerParams），避免 JSON 报告分享/落盘泄露目标站凭据
//   [P2-7] CSV 单元格公式注入转义（= + - @ \t \r 前缀加 ' 前缀）
//   [P0-FIX 2026-09-08] 可复现 PoC 证据链：导出时惰性给每条 vuln 挂 vuln.poc
//          （method/url/headers/body/curl/raw/note/payload/generatedAt），markdown 与
//          html 各新增「复现方式」小节；同时补上报告链接面的两处加固：
//          esc() 数字实体转义引号（PoC 要落进属性位）、safeHref/renderUrlLink 只放行
//          http(s) 且内网地址不可点击（报告在浏览器打开，点一下就是 SSRF）。
//          只增字段、只增小节：既有函数签名与既有输出行保持原样，调用方零感知。
// 其余逻辑与原文件一致（HTML 转义已存在且正确，原样保留）。
// ============================================================================

import { truncateLong } from '../core/logger.js';
import { buildPocEvidence } from '../engine/pocBuilder.js';
// [2026-09-13] 交付层：元信息/执行摘要/WAF 交战/修复建议+CVSS（markdown/html/csv 共用单一取数源）
import { buildDelivery } from './reportDelivery.js';

// 导出时单条证据/说明的最大长度（原逻辑不变）
const EVIDENCE_MAX = 4000;

// ============================================================================
// [P0-FIX 2026-09-08] 报告侧安全渲染原语（PoC 要塞进 <pre> 与属性位，故单独成组）
// ============================================================================

// 数字实体版转义：& < > " ' 全覆盖。
// 为什么不用 _escape：_escape 的 `"` → `&quot;` 形式已被既有测试锁定（行为不变原则），
// 而 PoC 文本要落进 title/href 等属性位，`"` → `&#34;`、`'` → `&#39;` 的数字实体在
// 「带引号属性」与「裸属性」两种上下文里都安全（&#34; 不会被任何解析器当引号闭合）。
const ESC_MAP = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&#34;', "'": '&#39;' };
export function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) => ESC_MAP[c]);
}

// 内网/回环地址判定：报告常在浏览器里打开，内网链接一点就是「报告文件 → SSRF」。
// 命中时渲染成 <code> 纯文本，保留可读性但不可点击。
export function isInternalHost(host) {
  const h = String(host || '').toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
  if (!h) return false;
  if (h === 'localhost' || h.endsWith('.localhost')) return true;
  if (h.endsWith('.local') || h.endsWith('.internal') || h.endsWith('.internaldomain')) return true;
  if (h === '::1' || h === '0.0.0.0' || h === '0') return true;
  if (/^(127|10|169\.254|192\.0\.0)\./.test(h)) return true;
  if (h.startsWith('192.168.')) return true;
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(h)) return true;
  return false;
}

// 可链接化判定：仅 http/https 允许进 href。javascript:/data:/file:/vbscript: 一律返回
// null（调用方降级为纯文本）。先剥掉控制字符与空白——`java\nscript:` 这类写法浏览器
// 会忽略换行继续按脚本协议解析，是过滤器的经典绕过面。
export function safeHref(url) {
  const raw = String(url ?? '').trim();
  if (!raw) return null;
  const cleaned = raw.replace(/[\u0000-\u0020\u007f]/g, '');
  if (!/^https?:\/\//i.test(cleaned)) return null;
  try {
    const u = new URL(cleaned);
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
    return cleaned;
  } catch {
    return null; // 非法 URL（含 host 里的 < > 等禁用字符）：不可点
  }
}

// 从 URL 中取主机名（内网判定用）；解析失败返回空串 → 调用方按「非内网」处理。
function hostOfUrl(u) {
  try {
    return new URL(String(u)).hostname;
  } catch {
    return '';
  }
}

// 目标/PoC URL 的 HTML 渲染：安全外链 → <a>；内网 → <code>；其余 → 纯文本。
// rel 加 noopener noreferrer：避免 target=_blank 反向拿到 window.opener。
export function renderUrlLink(url, label) {
  const text = esc(label ?? (url || '-'));
  const href = safeHref(url);
  if (!href) return text;
  if (isInternalHost(hostOfUrl(href))) return `<code>${text}</code>`;
  return `<a href="${esc(href)}" target="_blank" rel="noopener noreferrer nofollow">${text}</a>`;
}

// Markdown 内联代码：反引号必须转义，否则 payload/URL 里的 ` 会提前闭合行内代码。
function mdInline(s) {
  return String(s ?? '').replace(/`/g, '\\`');
}

// [2026-09-13] 顶层小助手：漏洞表行里的 CVSS 单元格文本（score + vector，同源 reportDelivery）
function cvssOfVuln(v, d) {
  const it = d.remediation.perVuln.find((x) => x.pointId === v.pointId && x.technique === v.technique);
  return it ? `${it.cvss.score}（${it.cvss.vector}）` : '-';
}

// Markdown 围栏：内容里可能出现反引号（payload 常含 ` 与 ```），围栏长度必须严格大于
// 正文中最长的反引号串，否则 PoC 会提前闭合围栏、把后续报告内容变成正文。
function mdFence(content, lang = '') {
  const runs = String(content || '').match(/`+/g) || [];
  const max = runs.reduce((m, r) => Math.max(m, r.length), 0);
  const tick = '`'.repeat(Math.max(3, max + 1));
  return `${tick}${lang}\n${content}\n${tick}`;
}

// 取「用于复现的那条 payload」：各检测器约定 payloads[0] 为命中样本
// （boolean=[真,假]、union=[命中 UNION,ORDER BY 确认]、error/stacked=[命中串]）。
function confirmedPayload(vuln) {
  if (typeof vuln?.evidencePayload === 'string' && vuln.evidencePayload) return vuln.evidencePayload;
  const list = Array.isArray(vuln?.payloads) ? vuln.payloads : [];
  const hit = list.find((p) => typeof p === 'string' && p.length);
  return hit || '';
}

// 以原始 vuln 对象为键的 PoC 缓存（WeakMap，随报告快照回收，不常驻内存）。
// 为何需要：同一次会话里 markdown / md 别名 / html 会被反复导出，而
// poc.generatedAt 是时间戳——不缓存则两次渲染文本不相等（CLI 的 md/markdown 等价
// 断言直接挂），且白白重算一遍 o(漏洞数) 的字符串拼接。
const POC_CACHE = new WeakMap();

// [P1-1] 导出前脱敏 target：剥离认证凭据与代理配置，只保留展示字段
// （baseUrl/method/bodyParams 等）。返回浅拷贝，不污染内存中的 report。
function sanitizeTargetForExport(target) {
  if (!target || typeof target !== 'object') return target;
  const out = { ...target };
  if (out.config && typeof out.config === 'object') {
    const { auth, proxy, ...rest } = out.config;
    out.config = {
      ...rest,
      auth: null, // 凭据不导出：仅保留「曾配置过」的展示需要时可用布尔标注
      proxy: null,
    };
  }
  delete out.cookieParams; // 目标会话 cookie 不导出
  delete out.headerParams; // 目标自定义头（可能含 Authorization）不导出
  if (out.db && typeof out.db === 'object' && out.db.connectionString) {
    out.db = { ...out.db, connectionString: '***' }; // 直连模式的连接串打码
  }
  return out;
}

// [P2-7] CSV 单元格转义：引号翻倍 + 公式前缀防护
function csvSafeCell(v) {
  let s = v === null || v === undefined ? '' : String(v);
  // 公式注入防护：以 = + - @ \t \r 开头的单元格加 ' 前缀（Excel/WPS 不再按公式解析）
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return `"${s.replace(/"/g, '""')}"`;
}

// 报告生成器：汇总 ReportModel、风险定级、JSON/HTML 导出
export class ReportGenerator {
  /** @internal 仅供 ScanManager 内部调用（含测试直接构造 ReportModel 的用例） */
  build(scanId, target, points, vulns, data) {
    const riskLevel = this.riskOf(vulns, data);
    return {
      scanId,
      target,
      startedAt: new Date().toISOString(),
      finishedAt: new Date().toISOString(),
      dbms: [...new Set(vulns.map((v) => v.dbms).filter(Boolean))].join(', ') || null,
      points,
      vulns,
      data: data || null,
      riskLevel,
      summary: {
        totalPoints: points.length,
        totalVulns: vulns.length,
        byTechnique: this._countBy(vulns, 'technique'),
        byRisk: this._countBy(vulns, 'riskLevel'),
      },
    };
  }

  riskOf(vulns, data) {
    if (data && this._hasData(data)) return 'Critical';
    if (vulns.some((v) => v.technique === 'stacked')) return 'Critical';
    if (
      vulns.some(
        (v) => v.technique === 'union' || v.technique === 'error' || v.technique === 'second_order'
      )
    ) {
      return 'High';
    }
    if (vulns.some((v) => v.technique === 'boolean' || v.technique === 'time')) {
      return 'Medium';
    }
    if (vulns.some((v) => v.technique === 'oob')) {
      return 'Medium';
    }
    if (vulns.length > 0) return 'Low';
    return 'Low';
  }

  _hasData(data) {
    return !!(
      (data.databases && data.databases.length) ||
      (data.tables && Object.keys(data.tables).length) ||
      (data.rows && Object.keys(data.rows).length)
    );
  }

  _countBy(arr, key) {
    const m = {};
    for (const x of arr) m[x[key]] = (m[x[key]] || 0) + 1;
    return m;
  }

  _truncate(report) {
    if (!report || !Array.isArray(report.vulns)) return report;
    const vulns = report.vulns.map((v) => {
      const out = { ...v };
      for (const key of ['evidence', 'description']) {
        out[key] = truncateLong(out[key], EVIDENCE_MAX);
      }
      return out;
    });
    return { ...report, vulns };
  }

  // [P0-FIX 2026-09-08] 惰性生成 PoC 证据：只在导出报告时计算，检测流程零侵入。
  // 顺序敏感——必须在 sanitizeTargetForExport 之前跑：PoC 要还原「扫描时真实发出的请求」，
  // 会话 Cookie / 自定义头缺一就无法复现登录后注入；脱敏只作用于 target 字段本身。
  // 返回浅拷贝（{ ...v, poc }），不写回调用方内存中的 report/vuln 对象，ScanManager 快照不受污染。
  /**
   * [P1-UX 2026-09-08] 对外只读入口：给「查看报告」接口挂上 PoC 证据（与导出同源、同缓存）。
   * 纯函数式返回浅拷贝，不写回 ScanManager 内存里的报告对象。
   * @param {object} report
   * @returns {object}
   */
  attachPoc(report) {
    return this._attachPoc(report);
  }

  _attachPoc(report) {
    const vulns = report && Array.isArray(report.vulns) ? report.vulns : null;
    if (!vulns || !vulns.length) return report;
    const points = (report && report.points) || [];
    const byId = new Map();
    for (const p of points) if (p && p.id != null) byId.set(p.id, p);
    // [P0-SEC 2026-09-08] 交付型报告可选把凭据头脱敏（config.pocRedactAuth=true）。
    // 默认关：PoC 要能直接复制跑；开启后 curl/raw/headers 统一打码。
    const redactAuth = !!(report && report.target && report.target.config && report.target.config.pocRedactAuth);
    let touched = false;
    const out = vulns.map((v) => {
      if (!v || typeof v !== 'object' || v.poc) return v; // 已有 poc（外部预生成）→ 不重复计算
      const cached = redactAuth ? undefined : POC_CACHE.get(v);
      if (cached) {
        touched = true;
        return { ...v, poc: cached }; // 同一份报告多次导出 → 逐字节一致（含 generatedAt）
      }
      try {
        const point = byId.get(v.pointId) || null;
        const poc = buildPocEvidence(report.target, point, confirmedPayload(v), { redactAuth });
        if (!redactAuth) POC_CACHE.set(v, poc);
        touched = true;
        return { ...v, poc };
      } catch {
        return v; // 任何异常都不让报告生成失败（PoC 是增强项，不是必需项）
      }
    });
    return touched ? { ...report, vulns: out } : report;
  }

  // [P1-1] 导出统一脱敏：先挂 PoC（缓存键是原始 vuln 对象，故须在截断拷贝前），
  // 再截断证据，最后剥离 target 凭据
  _forExport(report) {
    const r = this._truncate(this._attachPoc(report));
    if (!r.target) return r;
    return { ...r, target: sanitizeTargetForExport(r.target) };
  }

  // 导出 JSON（P1-1：target 已脱敏）
  toJSON(report) {
    return JSON.stringify(this._forExport(report), null, 2);
  }

  // 导出 CSV（P1-U3）：漏洞表 + 拖库数据两档，BOM 头 + [P2-7] 公式注入转义
  // [2026-09-13] 交付化：补 CVSS 与修复建议列（口径与 markdown/html 同源）
  toCSV(report) {
    const r = this._forExport(report);
    const d = buildDelivery(report);
    const cvssOf = new Map(d.remediation.perVuln.map((it) => [`${it.pointId}|${it.technique}`, it.cvss]));
    const remOf = new Map(d.remediation.perVuln.map((it) => [`${it.pointId}|${it.technique}`, it.actions]));
    const lines = [];
    lines.push('漏洞ID,注入点,技术,数据库,风险,CVSS,修复建议,说明');
    for (const v of r.vulns || []) {
      const key = `${v.pointId}|${v.technique}`;
      const cvss = cvssOf.get(key);
      const rem = (remOf.get(key) || []).join(' / ');
      lines.push(
        [
          v.id,
          v.pointId,
          v.technique,
          v.dbms || '',
          v.riskLevel,
          cvss ? `${cvss.score} ${cvss.vector}` : '',
          rem.replace(/[\r\n,]/g, ' '),
          (v.description || '').replace(/[\r\n,]/g, ' '),
        ]
          .map((c) => csvSafeCell(c))
          .join(',')
      );
    }
    const rows = r.data?.rows || {};
    if (Object.keys(rows).length) {
      lines.push('');
      lines.push('# 拖库数据');
      for (const [table, arr] of Object.entries(rows)) {
        if (!arr || !arr.length) continue;
        const cols = Object.keys(arr[0]);
        lines.push('');
        lines.push(`## ${table}`);
        lines.push(cols.join(','));
        for (const obj of arr) {
          lines.push(cols.map((c) => csvSafeCell(obj[c] ?? '')).join(','));
        }
      }
    }
    return '\uFEFF' + lines.join('\n');
  }

  // 导出 Markdown（原逻辑不变，仅 target 脱敏由 _forExport 覆盖）
  // [2026-09-13] 交付化（只增小节）：报告元信息/执行摘要/修复建议/WAF 交战 + 漏洞表 CVSS 列
  toMarkdown(report) {
    const r = this._forExport(report);
    const d = buildDelivery(report);
    const md = [];
    md.push(`# SQL 注入检测报告`);
    md.push('');
    md.push(`- 扫描ID：\`${report.scanId}\``);
    md.push(`- 目标：\`${report.target?.baseUrl || '-'}\``);
    md.push(`- 风险等级：**${report.riskLevel}**`);
    md.push(`- 数据库：${report.dbms || '-'}`);
    md.push(`- 注入点：${(report.points || []).length} · 漏洞：${(r.vulns || []).length}`);
    md.push('');
    md.push(...this._metaMarkdown(d));
    md.push(...this._execMarkdown(d));
    // [P0-FIX 2026-09-09] 结论可信度 + 本次抑制项（报告会被转出去，这两条不写就是默认「全测了且结论可靠」）
    md.push(...this._conclusionMarkdown(report));
    md.push('## 漏洞清单');
    md.push('');
    md.push('| 注入点 | 技术 | 数据库 | 风险 | CVSS | 说明 |');
    md.push('|---|---|---|---|---|---|');
    for (const v of r.vulns || []) {
      const cvss = cvssOfVuln(v, d);
      md.push(`| ${v.pointId} | ${v.technique} | ${v.dbms || '-'} | ${v.riskLevel} | ${cvss} | ${(v.description || '').replace(/\|/g, '\\|')} |`);
    }
    if (!(r.vulns || []).length) md.push('| - | - | - | - | - | 未发现漏洞 |');
    md.push('');
    md.push(...this._remediationMarkdown(d));
    md.push('## Payload 示例');
    md.push('');
    const payloads = (r.vulns || []).flatMap((v) => v.payloads || []);
    if (payloads.length) {
      for (const p of payloads) md.push(`- \`${p}\``);
    } else {
      md.push('- 无');
    }
    // [P0-FIX 2026-09-08] 复现方式：payload 字符串 → 可直接粘进终端的 curl + 可落盘导入的原始报文
    md.push(...this._pocMarkdown(r));
    md.push(...this._wafMarkdown(d));
    return md.join('\n');
  }

  // [P0-FIX 2026-09-09] 结论可信度与「本次被抑制的能力」。
  // 交付物首屏必须说清两件事：
  //   ① 0 漏洞到底是「没测出」还是「没测成」（verdict/verdictNote 来自 scanValidityGuard）；
  //   ② 哪些能力被安全护栏压住了（summary.constraints）——否则「已按最高风险等级测试」是不实陈述。
  // 缺省（旧报告无这两个字段）时整段不渲染，保持向后兼容。
  _conclusion(report) {
    const s = (report && report.summary) || {};
    const verdict = String(s.verdict || '');
    const note = String(s.verdictNote || '');
    const constraints = Array.isArray(s.constraints)
      ? s.constraints.filter((x) => typeof x === 'string' && x.trim())
      : [];
    if (!verdict && !note && !constraints.length) return null;
    return { verdict, note, constraints };
  }

  // ============================================================================
  // [2026-09-13] 交付层章节（markdown/html 共用取数源 buildDelivery；只增小节不改既有行）
  // ============================================================================

  // markdown 报告元信息
  _metaMarkdown(d) {
    const out = ['', '## 报告元信息', ''];
    out.push(`- 起止时间：${d.meta.startedAt || '-'} → ${d.meta.finishedAt || '-'}（耗时 ${d.meta.durationText || '-'}）`);
    out.push(`- 请求总数：${d.meta.requestCount ?? '-'} · 检测配置：level=${d.meta.level ?? '-'} · risk=${d.meta.risk ?? '-'} · 技术=${d.meta.techniques || '-'}`);
    out.push(`- 测试范围：${d.meta.scope}`);
    out.push('- 授权声明：本报告仅供授权安全测试使用；未获授权对任何系统进行扫描、测试或数据提取均可能违反法律法规。');
    out.push(`- 生成时间：${d.meta.generatedAt}`, '');
    return out;
  }

  // markdown 执行摘要（管理层视角：结果 + 影响实证 + 可信度 + 定库依据）
  _execMarkdown(d) {
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

  // markdown 修复建议（按注入点 + 通用基线）
  _remediationMarkdown(d) {
    const out = ['', '## 修复建议（Remediation）', ''];
    if (d.remediation.perVuln.length) {
      out.push('### 按注入点', '');
      for (const it of d.remediation.perVuln) {
        out.push(`**${it.pointId} · ${it.technique} · CVSS ${it.cvss.score} ${it.cvss.severity}**（\`${it.cvss.vector}\`）`, '');
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

  // markdown WAF 交战记录
  _wafMarkdown(d) {
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

  // HTML 报告元信息 + 执行摘要（合并渲染在既有结论卡之前）
  _deliveryHtml(d) {
    const esc = (s) => this._escape(String(s));
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

  // HTML 修复建议
  _remediationHtml(d) {
    const esc = (s) => this._escape(String(s));
    const per = d.remediation.perVuln
      .map((it) => {
        const actions = it.actions.map((a) => `<li>${esc(a)}</li>`).join('');
        return `<div class="poc"><p><b>${esc(it.pointId)} · ${esc(it.technique)}</b> · CVSS ${esc(it.cvss.score)} ${esc(it.cvss.severity)}（<code>${esc(it.cvss.vector)}</code>）</p><ul>${actions}</ul></div>`;
      })
      .join('');
    const general = d.remediation.general.map((a) => `<li>${esc(a)}</li>`).join('');
    return `<h2>修复建议（Remediation）</h2>
      ${per || '<p class="meta">未检出漏洞，以下为通用加固基线。</p>'}
      <p class="meta"><b>通用加固基线</b></p><ul>${general}</ul>
      <p class="meta">CVSS 口径：v3.1 启发式映射（按技术通道给分，环境项未设），供排期排序参考，非逐条人工评定。</p>`;
  }

  // HTML WAF 交战记录
  _wafHtml(d) {
    const esc = (s) => this._escape(String(s));
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

  _conclusionMarkdown(report) {
    const c = this._conclusion(report);
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
    if (c.constraints.length) {
      out.push('', '- 本次被抑制的能力（不代表已测试）：');
      for (const x of c.constraints) out.push(`  - ${x}`);
    }
    out.push('');
    return out;
  }

  _conclusionHtml(report) {
    const c = this._conclusion(report);
    if (!c) return '';
    const esc = (s) => this._escape(String(s));
    const items = c.constraints.map((x) => `<li>${esc(x)}</li>`).join('');
    const bad = c.verdict === 'inconclusive';
    // [P1-FIX 2026-09-12] 与 _conclusionMarkdown 同源：有命中时不展示 verdict（语义冲突会误导）
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
      ${items ? `<p class="meta">本次被抑制的能力（不代表已测试）：</p><ul>${items}</ul>` : ''}
    </div>`;
  }

  // [P0-FIX 2026-09-08] Markdown「复现方式」小节（只增小节，不改上面任何一行）
  _pocMarkdown(r) {
    const list = this._pocEntries(r);
    const out = ['', '## 复现方式（PoC）', ''];
    if (!list.length) {
      out.push('未发现漏洞，无可复现请求。', '');
      return out;
    }
    out.push('以下请求由引擎实际发送形态还原（含 prefix/suffix 与会话上下文），可直接回放验证“这不是误报”。', '');
    for (const it of list) {
      out.push(`### ${it.title}`, '');
      out.push(`- 请求：\`${mdInline(it.req)}\``);
      if (it.poc.payload) out.push(`- Payload：\`${mdInline(it.poc.payload)}\``);
      if (it.poc.note) out.push(`- 说明：${it.poc.note}`);
      out.push(`- 生成时间：${it.poc.generatedAt}`, '');
      if (it.poc.curl) {
        out.push('curl（复制即跑）：', '');
        out.push(mdFence(it.poc.curl, 'bash'), '');
      }
      if (it.poc.raw) {
        out.push(`原始报文（存为 \`${it.file}\` 后可用 -r 导入复现）：`, '');
        out.push(mdFence(it.poc.raw, 'http'), '');
      }
    }
    return out;
  }

  // [P0-FIX 2026-09-08] HTML「复现方式」小节：curl 一行 + <details> 折叠原始报文
  _pocHtml(r) {
    const list = this._pocEntries(r);
    if (!list.length) return '<p class="meta">未发现漏洞，无可复现请求。</p>';
    return list
      .map((it) => {
        const curl = it.poc.curl
          ? `<p class="meta">curl（复制即跑）</p><pre class="curl">${esc(it.poc.curl)}</pre>`
          : '';
        const raw = it.poc.raw
          ? `<details><summary>原始 HTTP 报文（存为 ${esc(it.file)} 后用 -r 导入复现）</summary><pre>${esc(it.poc.raw)}</pre></details>`
          : '';
        return `<div class="poc">
        <h3>${esc(it.title)}</h3>
        <p class="meta">请求：<code>${esc(it.method)}</code> ${renderUrlLink(it.poc.url, it.poc.url || '-')}</p>
        <p class="meta">Payload：${it.poc.payload ? `<code>${esc(it.poc.payload)}</code>` : '-'}</p>
        <p class="meta">${esc(it.poc.note || '')} · 生成于 ${esc(it.poc.generatedAt)}</p>
        ${curl}${raw}
      </div>`;
      })
      .join('\n');
  }

  // PoC 条目归一化：markdown / html 共用同一取数与标题规则，避免两侧漂移
  _pocEntries(r) {
    const out = [];
    let n = 0;
    for (const v of r.vulns || []) {
      const poc = v && v.poc;
      if (!poc) continue;
      n += 1;
      const point = String(v.pointId ?? '-');
      out.push({
        poc,
        title: `PoC-${n} · 注入点 ${point} · ${v.technique || '-'}`,
        file: `poc-${n}-${point}.txt`,
        method: poc.method || 'GET',
        req: `${poc.method || 'GET'} ${poc.url || '-'}`.trim(),
      });
    }
    return out;
  }

  // 导出 HTML（原逻辑不变：所有用户可控字段均已 _escape 转义，P3 已核验）
  // [2026-09-13] 交付化（只增小节）：报告元信息/执行摘要卡、漏洞表 CVSS 列、修复建议、WAF 交战
  toHTML(report) {
    const r = this._forExport(report);
    const d = buildDelivery(report);
    const rows = (r.vulns || [])
      .map(
        (v) => {
          const it = d.remediation.perVuln.find((x) => x.pointId === v.pointId && x.technique === v.technique);
          const cvss = it ? `${it.cvss.score} ${it.cvss.severity}` : '-';
          return `<tr>
        <td>${this._escape(v.pointId)}</td>
        <td>${this._escape(v.technique)}</td>
        <td>${this._escape(v.dbms || '-')}</td>
        <td class="${this._escape(String(v.riskLevel || 'low').toLowerCase())}">${this._escape(v.riskLevel)}</td>
        <td>${this._escape(cvss)}</td>
        <td>${this._escape(v.description || '')}</td>
      </tr>`;
        }
      )
      .join('');
    const payloads = (r.vulns || [])
      .flatMap((v) => v.payloads || [])
      .map((p) => '• ' + this._escape(p))
      .join('\n');
    // [P0-FIX 2026-09-08] 复现方式小节（只增不改上面既有行）
    const pocSection = this._pocHtml(r);
    const conclusionSection = this._conclusionHtml(report);
    const deliverySection = this._deliveryHtml(d);
    const remediationSection = this._remediationHtml(d);
    const wafSection = this._wafHtml(d);

    return `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
      <title>SQL 注入检测报告 ${report.scanId}</title>
      <style>
        body{font-family:system-ui,'Microsoft YaHei',sans-serif;margin:24px;color:#222}
        h1{font-size:20px}h2{font-size:16px;margin-top:24px}
        table{border-collapse:collapse;width:100%;margin-top:8px}
        th,td{border:1px solid #ccc;padding:6px 8px;font-size:13px;text-align:left}
        th{background:#f5f5f5}.critical{color:#c62828;font-weight:bold}
        .high{color:#ef6c00}.medium{color:#f9a825}.low{color:#9e9e9e}
        .meta{color:#666;font-size:13px}pre{background:#f7f7f7;padding:10px;border-radius:6px;white-space:pre-wrap;word-break:break-all}
        .footer{margin-top:32px;padding-top:12px;border-top:1px solid #eee;color:#999;font-size:12px;text-align:center}
        .poc{border:1px solid #e3e3e3;border-radius:6px;padding:4px 12px 10px;margin:12px 0}
        .verdict{border-left:4px solid #f9a825;background:#fffbe6;padding:6px 14px 10px;margin:12px 0;border-radius:4px}
        .verdict.bad{border-left-color:#c62828;background:#fff3f2}
        .verdict h2{margin:8px 0 4px;font-size:15px}
        .verdict ul{margin:4px 0 4px 18px;padding:0;font-size:13px;color:#5a4a00}
        .poc h3{font-size:14px;margin:10px 0 4px}details{margin:6px 0}summary{cursor:pointer;font-size:13px;color:#555}
        pre.curl{background:#0f1115;color:#d7e0ea;border-radius:6px;padding:10px;white-space:pre-wrap;word-break:break-all}
      </style></head><body>
      <h1>SQL 注入检测报告</h1>
      <p class="meta">扫描ID：${this._escape(report.scanId)} · 风险等级：<b>${this._escape(report.riskLevel)}</b> · 数据库：${this._escape(report.dbms || '-')}</p>
      <p class="meta">目标：${renderUrlLink(report.target?.baseUrl)} · 注入点：${(report.points || []).length} · 漏洞：${(report.vulns || []).length}</p>
      ${deliverySection}
      ${conclusionSection}
      <h2>漏洞清单</h2>
      <table><thead><tr><th>注入点</th><th>技术</th><th>数据库</th><th>风险</th><th>CVSS</th><th>说明</th></tr></thead>
      <tbody>${rows || '<tr><td colspan="6">未发现漏洞</td></tr>'}</tbody></table>
      ${remediationSection}
      <h2>Payload 示例</h2>
      <pre>${payloads || '无'}</pre>
      <h2>复现方式（PoC）</h2>
      ${pocSection}
      ${wafSection}
      <footer class="footer">本报告仅供授权安全测试使用。未获授权对任何系统进行扫描、测试或数据提取均可能违反法律法规，请勿用于非法用途。</footer>
      </body></html>`;
  }

  _escape(s) {
    return String(s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }
}

export default ReportGenerator;
