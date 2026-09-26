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
 * Markdown **文本位**（非代码位）的原语：掐掉「裸 HTML 标签」。
 *
 * 为什么必须有：`.md` 与 `.html` 一样是交付物，而绝大多数 md→html 转换器
 * （pandoc / markdown-it / md-to-pdf / GitHub）默认**保留行内原始 HTML** ——
 * 参数名、表名、PoC 标题里的一段 `<img src=x onerror=…>` 会在**阅读报告的机器上**执行。
 * HTML 侧一直有 `esc` 兜着，markdown 侧此前只转义 `|` 与换行（防拆表），
 * 于是同一份不可信数据在两个出口一个安全一个不安全。
 *
 * 只动 `<` `>` 与换行：CommonMark 的表格单元格与正文里，实体 `&lt;` 渲染回字面 `<`，
 * 可读性不损；`&` 不转义（未命名的 `&` 在 CommonMark 里本就是字面量，
 * 全转会把 `A&B 公司` 变成 `A&amp;B` 这种交付物噪声）。
 * **换行必须压成空格**：正文位的一个 \n 是「结构」而不是「内容」—— 实测表名
 * `users\n=HYPERLINK("http://evil","p")` 会凭空的造出一个新的 markdown 行，
 * 并把 mermaid 的 `S4["…"]` 标签从中间劈断（mermaid 标签里的裸换行会让整张图不渲染，
 * 而劈出来的后半行以 `=` 开头，在 CSV 侧就是一个公式单元格）。
 * 反引号不在这里处理 —— 代码位由 `mdCode`（同文件）按围栏长度另行负责。
 *
 * @param {unknown} s 不可信值（目标可控：参数名/表名/列名/PoC 标题）
 * @returns {string} 不会再开启 HTML 标签、也不会改变 markdown 结构的文本
 */
export function mdText(s) {
  return String(s ?? '')
    .replace(/[\r\n]+/g, ' ')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

/**
 * Markdown **代码位**（行内代码）：按内容里最长的反引号串决定围栏长度。
 *
 * 为什么不能用「反引号前加反斜杠」：CommonMark 明确规定行内代码内部**反斜杠没有转义
 * 含义**，所以 `\`` 是空操作 —— 内容里的一个 ` 就让围栏提前闭合，后半段掉回正文，
 * 接着就按 HTML 渲染。SQLi payload 大量含反引号（MySQL 标识符引用），这条路径天天能踩。
 *
 * 围栏长度 = 内容最长反引号串 + 1；内容首尾是反引号时两侧补一个空格
 * （CommonMark 会剥掉成对的一个前导/尾随空格，显示不受影响）。
 *
 * @param {unknown} s 不可信值（payload / 请求行 / 报文）
 * @returns {string} 自带围栏的完整行内代码（空值返回空串，不产出 ` ` 这种假代码位）
 */
export function mdCode(s) {
  const str = String(s ?? '');
  if (!str) return '';
  const runs = str.match(/`+/g) || [];
  const max = runs.reduce((m, r) => Math.max(m, r.length), 0);
  const tick = '`'.repeat(max + 1);
  const pad = /^`|`$/.test(str) ? ' ' : '';
  return `${tick}${pad}${str}${pad}${tick}`;
}

/**
 * 报告 HTML 的 CSP（以 `<meta http-equiv>` 形式注入）。
 *
 * 为什么要它：报告的防御目前是**逐点转义**（esc / mdText / safeHref 各管一处）。
 * 那种防线的失效方式是"将来某处新增一个出口忘了调"，而它一旦漏，后果不是"报告不好看"，
 * 是目标可控字符串在**读者的浏览器**里执行 —— 与本仓同日修掉的 markdown 裸 HTML 完全同源。
 * CSP 把这类单点失效从「任意脚本执行」降级成「某个标签渲染不出来」，是**结构性的第二道门**，
 * 不再依赖"每个改报告的人都不漏一处"。
 *
 * 策略按"报告只需要能把自己显示出来"来配：
 *   default-src 'none'    —— 默认拒绝一切外部取数（无脚本、无 XHR/fetch、无 iframe、无字体）
 *   style-src 'unsafe-inline' —— 本报告的样式表与 SVG 上的 style 属性都是内联的，必须放行
 *   img-src data:         —— 图仅允许 data: URI（离线交付物，不引外链）
 *   base-uri 'none'       —— 不让 <base> 把相对 URL 改到攻击者域
 *   form-action 'none'    —— 报告里没有表单，禁掉可外发的面
 * ⚠ 不用 frame-ancestors / sandbox / report-uri：按规范它们在 meta 传递里被忽略，
 *   写上去只会给后来人造成"这条已被保护"的错觉（真要防嵌套得走 HTTP 响应头）。
 */
export const REPORT_CSP_META =
  `<meta http-equiv="Content-Security-Policy" ` +
  `content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'">`;

/**
 * 内网/回环地址判定：报告常在浏览器里打开，内网链接一点就是「报告文件 → SSRF」。
 * 命中时渲染成 <code> 纯文本，保留可读性但不可点击。
 *
 * [2026-09-24 修] 原实现是**纯字面**判定，IPv6 形态全线漏网：
 *   `http://[::ffff:127.0.0.1]:9200/` → whatwg-url 会把它规范化成 `[::ffff:7f00:1]`
 *   （点分四段被换成十六进制两段！），于是 `^(127|10|…)\.` 这条正则**永远匹配不上**，
 *   报告里就留下一个可点击的回环链接 —— 而本函数的存在理由恰恰是「拦回环」。
 *   ULA（fc00::/7）与链路本地（fe80::/10）同样没人管。
 * 现按**字节**判：先把 IPv6 展开成 8 组 16 位，内嵌 IPv4（v4-mapped / v4-compatible /
 * 6to4）抽出四段后走同一套 v4 判据，再补 v6 自身的回环/ULA/链路本地/未指定。
 * 注意这是**展示层的保守启发式**（不做 DNS 解析，域名指向内网仍由扫描侧的 egressGuard 管），
 * 目标只一个：任何字面量写法的回环/私网地址都不能变成可点的东西。
 *
 * @param {string} host 主机名（IPv6 带方括号亦可）
 * @returns {boolean} 是否内网/回环地址
 */
export function isInternalHost(host) {
  const h = String(host || '').toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
  if (!h) return false;
  if (h === 'localhost' || h.endsWith('.localhost')) return true;
  if (h.endsWith('.local') || h.endsWith('.internal') || h.endsWith('.internaldomain')) return true;
  // 裸 '0' / '::1' 这类缩写形态保留原行为（既有测试钉着：isInternalHost('0') 必须为真）
  if (h === '0' || h === '0.0.0.0' || h === '::1') return true;
  if (h.includes(':')) {
    const groups = expandIpv6Groups(h);
    if (!groups) return false; // 解析不动的畸形串：本函数不判（safeHref 那一层会拒掉非法 URL）
    return isInternalIpv6Groups(groups);
  }
  // 点分四段（含 0x7f000001 / 2130706433 / 0177.0.0.1 这类形态：调用方传进来之前
  // 已经过 new URL() 规范化，这里再兜一层直接给四段的调用点）
  const octets = h.split('.').map((p) => Number(p));
  if (octets.length === 4 && octets.every((n) => Number.isInteger(n) && n >= 0 && n <= 255)) {
    return isInternalIpv4Octets(octets);
  }
  return /^(127|10|169\.254|192\.0\.0)\./.test(h)
    || h.startsWith('192.168.')
    || /^172\.(1[6-9]|2\d|3[01])\./.test(h);
}

/** IPv6 展开为 8 组 16 位（支持 `::` 压缩与点分四段尾）；解析失败返回 null */
function expandIpv6Groups(h) {
  let head = h;
  let tailParts = [];
  const lastColon = h.lastIndexOf(':');
  const maybeV4 = h.slice(lastColon + 1);
  if (maybeV4.includes('.')) {
    const octs = maybeV4.split('.').map((p) => Number(p));
    if (octs.length !== 4 || !octs.every((n) => Number.isInteger(n) && n >= 0 && n <= 255)) return null;
    head = h.slice(0, lastColon + 1);
    tailParts = [(octs[0] << 8) | octs[1], (octs[2] << 8) | octs[3]];
    h = head + '0:0'; // 占位，稍后用 tailParts 覆盖最后两组
  }
  const dbl = h.indexOf('::');
  let words;
  if (dbl >= 0) {
    const left = h.slice(0, dbl).split(':').filter(Boolean).map((x) => parseInt(x, 16));
    const right = h.slice(dbl + 2).split(':').filter(Boolean).map((x) => parseInt(x, 16));
    if (left.some(Number.isNaN) || right.some(Number.isNaN)) return null;
    const fill = 8 - left.length - right.length;
    if (fill < 1) return null;
    words = [...left, ...new Array(fill).fill(0), ...right];
  } else {
    words = h.split(':').map((x) => parseInt(x, 16));
    if (words.length !== 8 || words.some(Number.isNaN)) return null;
  }
  if (tailParts.length === 2) words = [...words.slice(0, 6), ...tailParts];
  return words.every((n) => Number.isInteger(n) && n >= 0 && n <= 0xffff) ? words : null;
}

/** 按 8 组 16 位判内网/回环（含内嵌 IPv4 的三种形态） */
function isInternalIpv6Groups(g) {
  const zeros = (from, to) => g.slice(from, to).every((x) => x === 0);
  if (zeros(0, 8)) return true; // :: 未指定地址
  if (zeros(0, 7) && g[7] === 1) return true; // ::1 回环
  if ((g[0] & 0xfe00) === 0xfc00) return true; // fc00::/7 ULA
  if ((g[0] & 0xffc0) === 0xfe80) return true; // fe80::/10 链路本地
  let v4 = null;
  if (zeros(0, 5) && g[5] === 0xffff && !zeros(6, 8)) v4 = g.slice(6, 8); // v4-mapped
  else if (zeros(0, 6)) v4 = g.slice(6, 8); // v4-compatible（::127.0.0.1 一类旧写法）
  else if (g[0] === 0x2002) v4 = g.slice(1, 3); // 2002::/16 6to4：内嵌原 v4 地址
  if (!v4) return false;
  return isInternalIpv4Octets([v4[0] >> 8, v4[0] & 0xff, v4[1] >> 8, v4[1] & 0xff]);
}

/** 唯一的 IPv4 私网/回环判据（点分四段版与 IPv6 内嵌版共用） */
function isInternalIpv4Octets(octets) {
  const [a, b, c] = octets;
  if (a === 127 || a === 10 || a === 0) return true; // 回环 / 私网 / "this network"
  if (a === 169 && b === 254) return true; // 链路本地
  if (a === 192 && b === 168) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  // 只收 192.0.0.0/24（IETF 协议分配）与 192.0.2.0/24（TEST-NET-1）：
  // 192.0.0.0/16 里还有 192.0.200.0/21 这类**公网**段，整段拦会把合法外部目标降成纯文本。
  if (a === 192 && b === 0 && (c === 0 || c === 2)) return true;
  if (a === 100 && b >= 64 && b <= 127) return true; // 100.64.0.0/10 CGNAT（云元数据侧常见跳板）
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
