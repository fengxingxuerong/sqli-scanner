// htmlSanitize —— 注入富 HTML 前的纵深防御清洗（不引入 DOMPurify 等新依赖）
//
// 背景：引擎侧 ReportGenerator.generateHtml 已对所有插值做实体转义（server 测试
// reportGenerator.escape.test.js 护栏）；本模块只作为前端消费侧的第二道闸——
// 任何将来把报告 HTML（report.html / AI 报告片段等）经 dangerouslySetInnerHTML
// 挂进 DOM 的地方，都必须先过一遍本函数。
//
// 策略（纯正则、不解析 DOM，避免在 jsdom/浏览器环境外行为漂移）：
//   1) 整体剥除 <script>…</script> 与 <iframe>/<object>/<embed>/<form> 等危险容器；
//   2) 剥除内联事件属性 on*="…" / on*='…' / on*=裸值；
//   3) 剥除 href/src/xlink:href/data/url() 中的 javascript:/vbscript:/data:text/html；
//   4) 剥除 <style> 块（可携带 expression/外联行为）与残留的 <!--> 条件注释。
// 已知局限：正则在畸形嵌套标签上不可能做到 HTML5 解析器等价强度；因此本函数定位是
// 「纵深防御 + 缓解」，不是安全边界——安全边界由引擎侧统一转义 + CSP 保证。

// 危险容器标签（连同其内容一并移除）
const DANGEROUS_BLOCK_RE = /<\s*(script|style|iframe|object|embed|form|template)\b[^>]*>[\s\S]*?<\s*\/\s*\1\s*>/gi;
// 未闭合的危险开标签（无对应闭合时至少把标签本身剥掉，防止属性里的 on* 残留）
const DANGEROUS_OPEN_RE = /<\s*\/?\s*(script|style|iframe|object|embed|form|template)\b[^>]*>/gi;
// 内联事件属性：onxxx= "…" / '…' / 裸词
const EVENT_ATTR_RE = /\son[a-z]{3,20}\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>"'`]+)/gi;
// 危险协议（href/src/action/xlink:href/background）
const BAD_PROTO_ATTR_RE = /\s(?:href|src|action|xlink:href|background|formaction|data)\s*=\s*(?:"\s*(?:javascript|vbscript|livescript|data\s*:\s*text\/html)[^"]*"|'\s*(?:javascript|vbscript|livescript|data\s*:\s*text\/html)[^']*'|(?:javascript|vbscript|livescript|data\s*:\s*text\/html)[^\s>"]*)/gi;
// CSS url() 内联脚本
// [2026-09-17 FIX] 原正则尾部 `\)?` 只吃**一个**右括号，输入 `url(javascript:alert(1))`
// 会残留一个 `)`；替换为 `url("")` 时其双引号还会提前闭合 HTML 的 style 属性 → 产出
// `style="background:url(""))"` 这种畸形片段。虽然 javascript: 已被剥离（不构成 XSS），
// 但清洗器产出破坏结构的 HTML 是次品。改为 `\)+` 吃掉全部右括号，替换串用不带引号的
// `url()`（合法空 CSS URL，不会闭合属性）。
const CSS_URL_JS_RE = /url\s*\(\s*['"]?\s*(?:javascript|vbscript|livescript)[^)]*\)+/gi;
// HTML 注释（条件注释曾是 IE 逃逸通道）
const COMMENT_RE = /<!--[\s\S]*?-->/g;

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
  out = out.replace(BAD_PROTO_ATTR_RE, ' href="#"');
  out = out.replace(EVENT_ATTR_RE, '');
  out = out.replace(CSS_URL_JS_RE, 'url()');
  // 事件属性清洗可能因嵌套引号漏网（如 <div "\nonclick=...">），对剩余 "javascript:"
  // 字面量做最后兜底：整体降为无害文本
  out = out.replace(/javascript\s*:/gi, 'javascript&#58;');
  return out;
}
