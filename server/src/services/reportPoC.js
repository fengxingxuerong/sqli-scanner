// =====================================================================
// reportPoC.js —— 可复现 PoC 证据链：生成 + 归一化 + markdown/html 渲染
//
// [大文件拆分 2026-09-21] 从 ReportGenerator.js 抽出（8 个方法 + 5 个私有辅助，~180 行）。
//
// 为什么这簇能安全外移（耦合度实测）：`_pointById` / `_pocRedactedForExport` 完全不
// 引用 this；`_pocEntries` 只调这两个；`_pocMarkdown` / `_pocHtml` 只调 `_pocEntries`；
// `_attachPoc` 不引用 this（只用模块级缓存 + pocBuilder）。全簇外部依赖仅
// `buildPocEvidence` 与 reportHtml 的两个纯函数。
//
// 这簇的共同语义：**PoC 的价值是「复制即跑」**。故脱敏默认关、异常一律降级
// （PoC 是增强项，任何失败都不能让报告生成失败）、同一份报告多次导出必须逐字节一致。
// 下面三处 FIX 注释都指向这三条，外移时逐字保留。
//
// 依赖方向：reportHtml.js（叶子） + engine/pocBuilder.js。不反向依赖 ReportGenerator。
// =====================================================================
import { buildPocEvidence } from '../engine/pocBuilder.js';
import { esc, renderUrlLink } from './reportHtml.js';

// Markdown 内联代码：反引号必须转义，否则 payload/URL 里的 ` 会提前闭合行内代码。
function mdInline(s) {
  return String(s ?? '').replace(/`/g, '\\`');
}

// Markdown 代码块围栏：内容里最长的反引号串决定围栏长度（+1），避免提前闭合。
function mdFence(content, lang = '') {
  const runs = /** @type {string[]} */ (String(content || '').match(/`+/g) || []);
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

// PoC 缓存（键 = 稳定字符串，见 pocCacheKey；Map + 容量上限，不常驻无界内存）。
// 为何需要：同一次会话里 markdown / md 别名 / html 会被反复导出，而
// poc.generatedAt 是时间戳——不缓存则两次渲染文本不相等（CLI 的 md/markdown 等价
// 断言直接挂），且白白重算一遍 o(漏洞数) 的字符串拼接。
// [FIX 2026-09-18 发布前 flaky] 原实现是 WeakMap（键 = vuln 对象引用）：只要上游
// （_enrich 未命中时的重建 / _truncate 的拷贝）产生过一次新对象，缓存就永久不命中，
// 于是每次导出都重算 poc.generatedAt → 「同一份报告两次导出逐字节一致」在跨毫秒时挂
// （实测单独复跑 3 次挂 1 次）。键必须与对象身份无关。
const POC_CACHE = new Map();
const POC_CACHE_MAX = 500;

/**
 * PoC 缓存键：scanId + 注入点 + 载荷 + 脱敏开关。
 * 不含对象引用，也不含时间——保证「同一份逻辑上的报告」在任何拷贝链路上都命中同一份 PoC。
 */
function pocCacheKey(report, v, redactAuth) {
  const scanId = String((report && report.scanId) || '');
  const pointId = String(v && v.pointId != null ? v.pointId : '');
  let payload = '';
  try {
    payload = String(confirmedPayload(v) ?? '');
  } catch {
    payload = '';
  }
  return `${scanId}|${pointId}|${payload}|${redactAuth ? 1 : 0}`;
}

function pocCacheSet(key, poc) {
  // Map 保持插入顺序：超出上限时淘汰最早写入的一条（WeakMap 换成 Map 后必须有界）
  if (POC_CACHE.size >= POC_CACHE_MAX) {
    const oldest = POC_CACHE.keys().next().value;
    if (oldest !== undefined) POC_CACHE.delete(oldest);
  }
  POC_CACHE.set(key, poc);
}

/**
 * 给每条漏洞惰性挂载 PoC 证据（method/url/headers/body/curl/raw/note/payload/generatedAt）。
 *
 * 三条行为契约（外移时逐字保留）：
 *   · 已有 `v.poc` 的漏洞不重算（外部预生成优先）；
 *   · 单条生成抛错 → 该条原样返回，**不让报告生成失败**（PoC 是增强项）；
 *   · 返回浅拷贝，不写回调用方内存中的 report。
 *
 * @param {object} report 报告对象
 * @returns {object} 挂好 PoC 的报告（无变化时返回原对象）
 */
export function attachPoc(report) {
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
    const key = pocCacheKey(report, v, redactAuth);
    const cached = redactAuth ? undefined : POC_CACHE.get(key);
    if (cached) {
      touched = true;
      return { ...v, poc: cached }; // 同一份报告多次导出 → 逐字节一致（含 generatedAt）
    }
    try {
      const point = byId.get(v.pointId) || null;
      const poc = buildPocEvidence(report.target, point, confirmedPayload(v), { redactAuth });
      if (!redactAuth) pocCacheSet(key, poc);
      touched = true;
      return { ...v, poc };
    } catch {
      return v; // 任何异常都不让报告生成失败（PoC 是增强项，不是必需项）
    }
  });
  return touched ? { ...report, vulns: out } : report;
}

/**
 * 按注入点 id 取 point（换 payload 重算 PoC 需要 point 的位置/形态）。
 * @param {object} r 报告对象
 * @param {string} pointId 注入点 id
 * @returns {object|null} point 或 null
 */
export function pointById(r, pointId) {
  return (r.points || []).find((p) => p.id === pointId) || null;
}

/**
 * 导出脱敏口径，[2026-09-17 FIX] 与 attachPoc 统一为同源判据。
 *
 * 原实现在导出路径下**恒返回 true**：target 已被 sanitizeTargetForExport 剥掉
 * cookieParams/headerParams，`'cookieParams' in target` 永远为 false，于是走到最后一行 true。
 * 后果是同一次交付里两条 PoC 自相矛盾——主命中 PoC 带真实会话凭据（可复制即跑），
 * 补充 payload PoC 的 Cookie 却被替换成占位符（复制过去跑不通，等于交了条废证据）。
 * 现口径：跟随 config.pocRedactAuth（与主命中 PoC 的既定设计一致，默认关——
 * PoC 的价值就在「复制即跑」；报告要外发时显式开该开关，主命中与补充 payload 一并脱敏）。
 *
 * @param {object} r 报告对象
 * @returns {boolean} 是否脱敏
 */
export function pocRedactedForExport(r) {
  if (r && r.pocRedacted === true) return true;
  return !!(r && r.target && r.target.config && r.target.config.pocRedactAuth);
}

/**
 * PoC 条目归一化：markdown / html 共用同一取数与标题规则，避免两侧漂移。
 *
 * [goal 批次 A-1] payloads 逐条展开：每个漏洞的每条 payload 各生成一条可复放 PoC
 * （主命中 = payloads[0]，与既有单条行为兼容；其余为同点补充 payload，均标注来源）。
 * buildPocEvidence 按每条 payload 重算请求形态，满足「可逐条手工复放验证」的交付口径。
 *
 * @param {object} r 报告对象
 * @param {object} [deps] 依赖：{ pointById, pocRedactedForExport }（默认用本模块实现）
 * @returns {object[]} PoC 条目列表
 */
export function pocEntries(r, deps = {}) {
  const byId = deps.pointById || pointById;
  const redacted = deps.pocRedactedForExport || pocRedactedForExport;
  const out = [];
  let n = 0;
  for (const v of r.vulns || []) {
    const base = v && v.poc;
    if (!base) continue;
    n += 1;
    const point = String(v.pointId ?? '-');
    const list = Array.isArray(v.payloads) && v.payloads.length ? v.payloads : [base.payload];
    const seen = new Set();
    let m = 0;
    for (const pl of list) {
      const p = String(pl ?? '');
      if (!p || seen.has(p)) continue;
      seen.add(p);
      m += 1;
      const label = m === 1 ? '主命中' : `补充 payload ${m}`;
      let poc = base;
      if (p !== base.payload) {
        // 同注入点换 payload 重算完整复放请求（headers/body/curl/raw 全部跟随）
        poc = buildPocEvidence(r.target || {}, byId(r, v.pointId) || {}, p, { redactAuth: redacted(r) });
        // [2026-09-17 FIX] 同批证据共用主命中的生成时间戳。
        // 原实现让补充 payload 的 PoC 携带自身 Date.now()，而主命中 PoC 走 WeakMap 缓存——
        // 于是「同一份报告两次渲染逐字节一致」在跨毫秒边界时必然失败（实测 5 次挂 2 次，
        // poc.evidence.test.js 的确定性用例即被此击中）。一次导出产出的证据链属于同一时刻，
        // 共用时间戳在语义上也更正确。
        poc = { ...poc, generatedAt: base.generatedAt };
      }
      out.push({
        poc,
        // [2026-09-17] 标题带受影响参数：PoC 清单要能直接对上「哪个参数中招」，
        // 此前只有内部 pointId hash，手工复现时需回查 JSON 才能确认。
        title: `PoC-${n}-${m} · 注入点 ${point}${v.param ? `（参数 ${v.param}）` : ''} · ${v.technique || '-'} · ${label}`,
        file: `poc-${n}-${m}-${point}.txt`,
        method: poc.method || 'GET',
        req: `${poc.method || 'GET'} ${poc.url || '-'}`.trim(),
        vulnId: v.id || '',
        label,
      });
    }
  }
  return out;
}

/**
 * Markdown「复现方式」小节（只增小节，不改既有行）。
 * @param {object} r 报告对象
 * @param {object} [deps] 依赖：{ pocEntries }
 * @returns {string[]} markdown 行数组
 */
export function pocMarkdown(r, deps = {}) {
  const getEntries = deps.pocEntries || ((x) => pocEntries(x));
  const list = getEntries(r);
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

/**
 * HTML「复现方式」小节：curl 一行 + <details> 折叠原始报文。
 * @param {object} r 报告对象
 * @param {object} [deps] 依赖：{ pocEntries }
 * @returns {string} HTML 片段
 */
export function pocHtml(r, deps = {}) {
  const getEntries = deps.pocEntries || ((x) => pocEntries(x));
  const list = getEntries(r);
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
