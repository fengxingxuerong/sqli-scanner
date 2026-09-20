// =====================================================================
// reportHtml.js —— 报告侧 HTML 渲染原语（安全边界，不是美化）
//
// [大文件拆分 2026-09-21] 从 ReportGenerator.js 抽出（原 30–103 行 + _escape 相关）。
//
// 为什么单独成模块（不只是行数）：
//   1. **打破潜在的循环依赖**：reportPoC.js 需要 `esc` / `renderUrlLink`，
//      而 ReportGenerator.js 又要 import reportPoC.js —— 若这两个函数留在
//      ReportGenerator 里就会形成环。放到无依赖的叶子模块后，依赖方向是单向的：
//        reportHtml.js  →  (无)
//        reportPoC.js   →  reportHtml.js, engine/pocBuilder.js
//        ReportGenerator.js → reportHtml.js, reportPoC.js, reportDelivery.js
//   2. 这四个函数是**安全边界**：报告常在浏览器里打开，而 PoC 文本、URL、参数名
//      全部来自被测目标（不可信输入）。集中在无依赖的叶子模块后，可以独立穷举测试。
//
// 职责：只做「不可信字符串 → 可安全嵌入 HTML 的文本」。不取数、不排版、不碰报告结构。
// =====================================================================

// 数字实体版转义：& < > " ' 全覆盖。
// 为什么不用 ReportGenerator._escape：_escape 的 `"` → `&quot;` 形式已被既有测试锁定
// （行为不变原则），而 PoC 文本要落进 title/href 等属性位，`"` → `&#34;`、
// `'` → `&#39;` 的数字实体在「带引号属性」与「裸属性」两种上下文里都安全
// （&#34; 不会被任何解析器当引号闭合）。
const ESC_MAP = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&#34;', "'": '&#39;' };

/**
 * 数字实体版 HTML 转义。
 * @param {unknown} s 待转义值（null/undefined → 空串）
 * @returns {string} 可安全嵌入 HTML 文本与属性位的字符串
 */
export function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) => ESC_MAP[c]);
}

/**
 * 内网/回环地址判定：报告常在浏览器里打开，内网链接一点就是「报告文件 → SSRF」。
 * 命中时渲染成 <code> 纯文本，保留可读性但不可点击。
 * @param {string} host 主机名（IPv6 带方括号亦可）
 * @returns {boolean} 是否内网/回环地址
 */
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

/**
 * 可链接化判定：仅 http/https 允许进 href。javascript:/data:/file:/vbscript: 一律返回
 * null（调用方降级为纯文本）。先剥掉控制字符与空白——`java\nscript:` 这类写法浏览器
 * 会忽略换行继续按脚本协议解析，是过滤器的经典绕过面。
 * @param {string} url 待判定 URL
 * @returns {string|null} 可安全放进 href 的 URL，或 null（表示不可链接）
 */
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

/**
 * 目标/PoC URL 的 HTML 渲染：安全外链 → <a>；内网 → <code>；其余 → 纯文本。
 * rel 加 noopener noreferrer：避免 target=_blank 反向拿到 window.opener。
 * @param {string} url 目标 URL
 * @param {string} [label] 显示文本（缺省用 url）
 * @returns {string} HTML 片段
 */
export function renderUrlLink(url, label) {
  const text = esc(label ?? (url || '-'));
  const href = safeHref(url);
  if (!href) return text;
  if (isInternalHost(hostOfUrl(href))) return `<code>${text}</code>`;
  return `<a href="${esc(href)}" target="_blank" rel="noopener noreferrer nofollow">${text}</a>`;
}
