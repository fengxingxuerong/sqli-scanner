// =====================================================================
// formParse.js — HTML 表单解析（TargetParser 表单族，D326 纯搬移）
//
// 原 TargetParser 1190 行距 arch 1200 硬上限 10 行。本族 5 个方法 + CSRF_RE +
// pickSelectValue 无实例状态依赖（只经 this._attr → attrValue，已收敛为单一事实源），
// 整体搬到此模块；TargetParser 保留 5 个薄委托，类内与测试侧调用点零改动。
//
// 判据注释按原文保留（D120/D171/D168 的静默假阴性教训不因搬移丢失）。
// =====================================================================
import { attrValue } from './crawler.js';

// 反 CSRF 字段名正则（命中即记为 csrfTokenName）
const CSRF_RE = /^(csrf|_token|__RequestVerificationToken|authenticity_token)$/i;

// 解析 HTML 中的 <form>，返回 { method, action, values, csrfTokenName }[]
export function parseForms(html, baseUrl) {
  const forms = [];
  const formRe = /<form\b([^>]*)>([\s\S]*?)<\/form>/gi;
  let fm;
  while ((fm = formRe.exec(html))) {
    const formTag = fm[1] || '';
    const inner = fm[2] || '';
    const method = (attrValue(formTag, 'method') || 'GET').toUpperCase() === 'POST' ? 'POST' : 'GET';
    const actionRaw = attrValue(formTag, 'action') || '';
    let action;
    try {
      action = actionRaw ? new URL(actionRaw, baseUrl).toString() : baseUrl;
    } catch {
      action = baseUrl;
    }

    const collected = collectInputs(inner);
    const values = collected.values;
    collectTextareas(inner, values, collected);
    // [D171 2026-10-26] `<select>` 字段：筛选/排序表单最常见控件，此前整体不采集
    // （D112 注释里登记为「后续按需补」）。缺它时这类表单只剩按钮字段 ⇒ 0 个注入点。
    collectSelects(inner, values, collected);
    // injectableNames：要生成**注入点**的字段（排除按钮 —— 按钮值由服务端校验，
    // 拿它当注入点只会产生噪声；但它仍在 values 里随请求发出，见 collectInputs 注释）。
    const injectableNames = Object.keys(values).filter((n) => !collected.buttonNames.has(n));
    // [D168 2026-10-26] 表单编码类型：`enctype="multipart/form-data"` 的上传表单若按
    // urlencoded 提交，目标直接 415/400 ⇒ 字段从未进业务逻辑（与 D159 同一类静默假阴性）。
    const enctype = (attrValue(formTag, 'enctype') || '').toLowerCase();
    forms.push({ method, action, values, injectableNames, csrfTokenName: collected.csrfTokenName, enctype });
  }
  return forms;
}

/**
 * 采集表单内 `<input>`：返回 { values, buttonNames, csrfTokenName }。
 *
 * [D120 2026-10-21] 提交/按钮类控件**必须采集进 values**，只是不作为注入点。
 * 反证（外部裁判 DVWA low，`vulnerabilities/sqli/source/low.php`）：
 *   `if (isset($_REQUEST['Submit'])) { $id = $_REQUEST['id']; ... }`
 *   ⇒ 缺 Submit 时查询**根本不执行**，注入 payload 不进 SQL，响应与基线完全一致
 *   ⇒ 扫描器静默 0 检出（实测：`--forms` 发现 body:id 点、formValues 只有 {"id":""}、
 *      367 请求 0 漏洞；补齐 Submit 后同一目标检出 3 条）。
 * 这与 D112 是同一类缺陷（「POST body 的伴随字段必须随注入请求发出」）——
 * 那次修的是 --body 生成点，这次补上表单爬取路径。
 * hidden 仍需采集（含 CSRF token），与按钮一并随请求发出。
 * @param {string} inner 表单内 HTML
 * @returns {{ values: Record<string, string>, buttonNames: Set<string>, csrfTokenName: string | null }}
 */
export function collectInputs(inner) {
  /** @type {Record<string, string>} */
  const values = {};
  const buttonNames = new Set();
  let csrfTokenName = null;
  const inputRe = /<input\b([^>]*)\/?>/gi;
  let im;
  while ((im = inputRe.exec(inner))) {
    const tag = im[1] || '';
    const type = (attrValue(tag, 'type') || 'text').toLowerCase();
    const name = attrValue(tag, 'name');
    if (!name) continue; // 无 name 的 input 既不是参数也不是触发条件
    const value = attrValue(tag, 'value') || '';
    const isButton = ['submit', 'button', 'image', 'reset'].includes(type);
    if (isButton) buttonNames.add(name);
    values[name] = value;
    if (!csrfTokenName && CSRF_RE.test(name)) csrfTokenName = name;
  }
  return { values, buttonNames, csrfTokenName };
}

/**
 * [P1-FIX 2026-09-07] 补 `<textarea>` 采集：多行文本（评论正文/简介/资料）是二阶注入
 * 最典型的存储字段——此前只解析 `<input>`，textarea 字段整体缺失 → 二阶存储探针存错
 * 参数（存进 item_id 而非正文 body）→ 存储值根本进不了被拼接的 SQL → 二阶必漏
 * （real-world-lab 实测）。取值语义：标签间文本即默认值；同名时 input 优先（不覆盖）。
 * `<select>` 未采集（取值需解析 selected option，场景较少，后续按需补）。
 * @param {string} inner 表单内 HTML
 * @param {Record<string,string>} values 就地写入（不改已有的 input 同名值）
 * @param {{csrfTokenName: string|null}} collected 就地回填 CSRF 名
 */
export function collectTextareas(inner, values, collected) {
  const taRe = /<textarea\b([^>]*)>([\s\S]*?)<\/textarea>/gi;
  let tm;
  while ((tm = taRe.exec(inner))) {
    const name = attrValue(tm[1] || '', 'name');
    if (!name) continue; // 无 name 的 textarea 不可作为注入点
    if (values[name] == null) values[name] = (tm[2] || '').trim();
    if (!collected.csrfTokenName && CSRF_RE.test(name)) collected.csrfTokenName = name;
  }
}

/**
 * [D171 2026-10-26] 采集表单内 `<select>`：取 selected option 的 value，没有 selected
 * 就取第一个有 value 的 option（浏览器默认行为）。
 *
 * 为什么重要：筛选/排序表单的注入面经常就在下拉值上（`sort=name`、`status=1`），
 * 而此前只解析 `<input>` / `<textarea>` ⇒ 这类表单只剩按钮字段 ⇒ **0 个注入点**，
 * 报告写「未检出」。同名时 input 优先（与 textarea 同口径）。
 * 边界：只认有 `value` 属性的 option（无 value 的 option 浏览器会用文本，文本里可能含
 * 空格/中文，当注入点会发畸形报文）；`multiple` 多选只取第一个（未验证）。
 * @param {string} inner 表单内 HTML
 * @param {Record<string,string>} values 就地写入（不改已有的 input/textarea 同名值）
 * @param {{csrfTokenName: string|null}} collected 就地回填 CSRF 名
 */
export function collectSelects(inner, values, collected) {
  const selRe = /<select\b([^>]*)>([\s\S]*?)<\/select>/gi;
  let sm;
  while ((sm = selRe.exec(inner))) {
    const name = attrValue(sm[1] || '', 'name');
    if (!name || values[name] != null) continue;
    const picked = pickSelectValue(sm[2] || '');
    if (picked == null) continue;
    values[name] = picked;
    if (!collected.csrfTokenName && CSRF_RE.test(name)) collected.csrfTokenName = name;
  }
}

/**
 * 把表单字段全部写进 URL 的 query（GET 表单用；同名参数覆盖）。
 * @param {string} action 表单 action（绝对地址）
 * @param {Record<string,string>} values 表单字段
 * @returns {string} 带完整 query 的 URL（解析失败原样返回）
 */
export function urlWithValues(action, values) {
  try {
    const u = new URL(action);
    for (const [k, v] of Object.entries(values || {})) u.searchParams.set(k, v ?? '');
    return u.toString();
  } catch {
    return action;
  }
}

/**
 * [D171] 从一个 `<select>` 的内部 HTML 里取要提交的 option value。
 *
 * 浏览器语义：有 `selected` 就取它；否则取第一个选项。只认带 `value` 属性的 option ——
 * 无 value 的 option 浏览器会提交其**文本**（可能含空格/中文），当注入点会发畸形报文。
 * @param {string} inner `<select>` 与 `</select>` 之间的 HTML
 * @returns {string|null} 取不到返回 null
 */
function pickSelectValue(inner) {
  const optRe = /<option\b([^>]*)>/gi;
  let first = null;
  let om;
  while ((om = optRe.exec(inner))) {
    const tag = om[1] || '';
    const vm = /value\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i.exec(tag);
    if (!vm) continue;
    const value = vm[1] ?? vm[2] ?? vm[3] ?? '';
    if (first == null) first = value;
    if (/\bselected\b/i.test(tag)) return value;
  }
  return first;
}
