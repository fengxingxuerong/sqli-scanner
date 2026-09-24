// htmlSanitize —— 注入富 HTML 前的纵深防御清洗（不引入 DOMPurify 等新依赖）
//
// 背景：引擎侧 ReportGenerator.generateHtml 已对所有插值做实体转义（server 测试
// reportGenerator.escape.test.js 护栏）；本模块只作为前端消费侧的第二道闸——
// 任何将来把报告 HTML（report.html / AI 报告片段等）经 dangerouslySetInnerHTML
// 挂进 DOM 的地方，都必须先过一遍本函数。
//
// 策略（块级用正则、属性级在**标签内部**逐 token 走，不解析 DOM）：
//   1) 整体剥除 <script>…</script> 与 <iframe>/<object>/<embed>/<form> 等危险容器；
//   2) 在标签内按「分隔符 + 属性名 + 可选值」切 token，剥除 on* 事件属性 ——
//      分隔符含空白与 `/`，且允许为空（HTML5 会容错恢复 `src="x"onerror=…`）；
//      值整体吃掉，所以 `data-x="a/onmouseover=b()"` 不会被误当成属性边界；
//   3) 剥除 href/src/xlink:href/data/url() 中的 javascript:/vbscript:/data:text/html；
//   4) 剥除 <style> 块（可携带 expression/外联行为）与残留的 <!--> 条件注释。
// 已知局限：属性级清洗按 HTML5 的宽容解析对齐，但整段仍是文本级处理，畸形嵌套
// （如属性值里未闭合的引号）不可能做到 HTML5 解析器等价强度；因此本函数定位是
// 「纵深防御 + 缓解」，不是安全边界——安全边界由引擎侧统一转义 + CSP 保证。

// 危险容器标签（连同其内容一并移除）
const DANGEROUS_BLOCK_RE = /<\s*(script|style|iframe|object|embed|form|template)\b[^>]*>[\s\S]*?<\s*\/\s*\1\s*>/gi;
// 未闭合的危险开标签（无对应闭合时至少把标签本身剥掉，防止属性里的 on* 残留）
const DANGEROUS_OPEN_RE = /<\s*\/?\s*(script|style|iframe|object|embed|form|template)\b[^>]*>/gi;
// HTML 注释（条件注释曾是 IE 逃逸通道）
const COMMENT_RE = /<!--[\s\S]*?-->/g;

// 事件属性名：on + 字母（HTML5 里 on 开头的属性一律是事件回调，没有例外）
const EVENT_NAME_RE = /^on[a-z]{1,20}$/i;
// 需要查协议的属性名
const URL_ATTR_RE = /^(?:xlink:href|href|src|action|background|formaction|data)$/i;
// 危险协议值（允许引号内前导空白与 `javascript&#58;` 这种实体写法）
const BAD_PROTO_VALUE_RE = /^\s*(?:javascript|vbscript|livescript|data\s*:\s*text\/html)/i;
// CSS url() 内联脚本
// [2026-09-17 FIX] 原正则尾部 `\)?` 只吃**一个**右括号，输入 `url(javascript:alert(1))`
// 会残留一个 `)`；替换为 `url("")` 时其双引号还会提前闭合 HTML 的 style 属性 → 产出
// `style="background:url(""))"` 这种畸形片段。虽然 javascript: 已被剥离（不构成 XSS），
// 但清洗器产出破坏结构的 HTML 是次品。改为 `\)+` 吃掉全部右括号，替换串用不带引号的
// `url()`（合法空 CSS URL，不会闭合属性）。
const CSS_URL_JS_RE = /url\s*\(\s*['"]?\s*(?:javascript|vbscript|livescript)[^)]*\)+/gi;

// 单个属性 token：分隔符（空白或 '/'）+ 名字 + 可选 `=值`（双引号 / 单引号 / 裸值）。
// 用 sticky 逐 token 走，命中即整段原样保留或整段丢弃 —— 关键点是**值被当成一个整体吃掉**，
// 所以 `data-x="a/onmouseover=b()"` 里引号内的文本不会被误当成属性边界（反过来，
// 分隔符允许为空，才能认出 `src="x"onerror=…` 这种浏览器会宽容恢复的写法）。
const ATTR_TOKEN_RE =
  /([ \t\n\r\f/]*)([^\s"'>/=]+)((?:[ \t]*=[ \t]*)("[^"]*"|'[^']*'|[^\s"'>]*))?/y;

/** 扫出一个标签片段的结束位置：从 `<` 起，跳过引号内的 `>`，直到未加引号的 `>` 或串尾 */
function scanTagEnd(html: string, start: number): number {
  let quote = '';
  for (let i = start + 1; i < html.length; i++) {
    const c = html[i];
    if (quote) {
      if (c === quote) quote = '';
      continue;
    }
    if (c === '"' || c === "'") quote = c;
    else if (c === '>') return i + 1;
  }
  return html.length;
}

/**
 * 逐标签走查：只对「真的是标签」的片段做属性清洗，其余文本原样保留。
 * 不能写成 `html.replace(/<.../, cleanTag)` —— 任何含 `*` 的贪婪写法都会从第一个 `<`
 * 一路吃到串尾，把标签后面的正文一起吃掉。
 */
function cleanTags(html: string): string {
  let out = '';
  let i = 0;
  while (i < html.length) {
    const lt = html.indexOf('<', i);
    if (lt < 0) break;
    out += html.slice(i, lt);
    const next = html[lt + 1] ?? '';
    // HTML5：`<` 后面不是字母也不是 `/` 时是字面量小于号（如 `a < b`），不当标签处理
    if (next && !/[a-zA-Z/]/.test(next)) {
      out += '<';
      i = lt + 1;
      continue;
    }
    const end = scanTagEnd(html, lt);
    out += cleanTag(html.slice(lt, end));
    i = end;
  }
  return out + html.slice(i);
}

/**
 * 清洗单个标签片段（`<` … `>`）：剥除事件属性、把危险协议降为 `href="#"`。
 * 良性标签逐字节原样返回（保证幂等、不误杀正常内容）。
 */
function cleanTag(seg: string): string {
  let i = 1; // 跳过 '<'
  if (seg[i] === '/') i++; // '</div>'
  while (i < seg.length && !/[ \t\n\r\f/>]/.test(seg[i])) i++; // 标签名
  let out = seg.slice(0, i);
  while (i < seg.length && seg[i] !== '>') {
    ATTR_TOKEN_RE.lastIndex = i;
    const m = ATTR_TOKEN_RE.exec(seg);
    if (!m) {
      // 尾部的 '/>'、'>' 或畸形残骸：原样保留
      out += seg.slice(i);
      break;
    }
    const name = m[2];
    const value = m[4];
    const end = ATTR_TOKEN_RE.lastIndex;
    if (EVENT_NAME_RE.test(name)) {
      // 事件属性整段丢弃（含前导分隔符，故 `<div onclick="a()">` → `<div>`）
    } else if (URL_ATTR_RE.test(name) && value && BAD_PROTO_VALUE_RE.test(stripQuotes(value))) {
      out += ' href="#"';
    } else {
      out += seg.slice(i, end);
    }
    i = end;
  }
  return out.endsWith('>') || i >= seg.length ? out : `${out}>`;
}

function stripQuotes(v: string): string {
  const q = v[0];
  return (q === '"' || q === "'") && v.length > 1 && v[v.length - 1] === q ? v.slice(1, -1) : v;
}

/**
 * 清洗准备注入 DOM 的 HTML 片段：剥除 script 块、on* 内联事件与危险协议，返回安全子集。
 * 输入非字符串时返回空串（调用方按「无内容」处理，不渲染空白 undefined）。
 */
export function sanitizeInjectedHtml(html: unknown): string {
  if (typeof html !== 'string' || !html) return '';
  let out = html;
  // 先删成对危险块，再处理未闭合残骸；协议清洗放在属性级，双保险
  out = out.replace(DANGEROUS_BLOCK_RE, '');
  out = out.replace(DANGEROUS_OPEN_RE, '');
  out = out.replace(COMMENT_RE, '');
  // 属性级清洗必须**限定在标签内部**并按属性 token 走：
  // [2026-09-24 FIX] 此前用 /\son[a-z]{3,20}\s*=/ 全文扫，要求属性名前必须有空白，
  // 而 HTML5 允许两种非空白的属性分隔写法 —— `<svg/onload=…>`（斜杠）与
  // `<img src="x"onerror=…>`（引号结束后直接接下一个属性，浏览器会容错恢复）。
  // 两种写法都能整段穿过旧清洗器，实测 `<svg/onload=alert(1)>` 原样输出。
  // 同时旧写法会在 `<div data-x="a/onmouseover=b()">` 这类**值内部**误伤（若只把
  // 分隔符放宽到 [\s/] 就会咬这一口），所以改成标签内逐 token 解析而不是全文正则。
  out = cleanTags(out);
  out = out.replace(CSS_URL_JS_RE, 'url()');
  // 事件属性清洗可能因嵌套引号漏网（如 <div "\nonclick=...">），对剩余 "javascript:"
  // 字面量做最后兜底：整体降为无害文本
  out = out.replace(/javascript\s*:/gi, 'javascript&#58;');
  return out;
}
