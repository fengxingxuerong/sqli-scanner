// ============================================================================
// pocBuilder.js —— 可复现 PoC 证据链构造器 [P0-FIX 2026-09-08]
//
// 实战痛点：报告里只有一串 payload 文本，交付给客户时既无法直接复现，也无法证明
// 「这不是误报」。本模块把「payload + 注入点 + 目标」还原成一条完整可回放的 HTTP
// 请求，并给出三种等价表达：
//   ① 结构化 { method, url, headers, body } —— JSON 报告 / 前端展示直接消费
//   ② 单行 curl                              —— 复制即跑（带 -i 便于把响应头一起取证）
//   ③ 原始 HTTP 报文                          —— 存成文件后用 sqlmap -r（或本引擎的
//                                               core/requestFileParser.js）导入复现
//
// 设计约束（为什么这样写）：
//   - 纯函数、零 IO、零异常：任何一步失败都降级返回，绝不把报告生成打断；检测流程
//     完全不感知本模块（由 ReportGenerator 在导出时惰性调用）。
//   - 必须复用 injection.js#buildInjectionRequest：prefix/suffix 包裹、jsonBody 嵌套
//     通道、会话 Cookie 无条件携带、--hpp 双份、已编码 payload 免二次编码等既有语义
//     全部继承。PoC 与扫描时真实发出的请求必须逐字节一致，否则「可复现」是空话——
//     也因此绝不能在报告侧另行拼 URL（那条路径迟早与引擎漂移）。
//   - shell 安全：payload 是攻击者可控字符串，curl 行会被工程师直接粘进终端执行，
//     因此所有插值一律单引号包裹 + '\'' 转义，禁止 $() / 反引号 / 换行逃逸出引号。
//   - 原始报文与 requestFileParser 的解析规则互为逆运算（请求行 + Header 行 + 空行 +
//     body，Host 头必带且 https 显式保留 :443——解析侧靠端口反推协议）。
// ============================================================================

import { URL } from 'url';
import { buildInjectionRequest } from './injection.js';

// 语义上不应携带任何方法覆盖提示的方法（HEAD/OPTIONS 无体）
const NO_BODY_METHODS = new Set(['HEAD', 'OPTIONS']);

// 大小写不敏感取头（HTTP 头名不区分大小写，target.headerParams 常出现 Cookie/cookie 混用）
function headerGet(headers, name) {
  const ln = String(name).toLowerCase();
  for (const [k, v] of Object.entries(headers || {})) {
    if (String(k).toLowerCase() === ln) return v;
  }
  return undefined;
}

// 头值里的 CR/LF 必须压掉：换行会破坏报文分帧（curl 直接拒绝含换行的 -H，
// 原始报文里则会被解析成额外头/请求走私），PoC 首先得是一条「合法请求」。
function headerValue(v) {
  return String(v ?? '').replace(/[\r\n]+/g, ' ');
}

// Host 头：端口非默认时保留，https 的 443 显式写出——requestFileParser [B-9a] 用
// 「Host 以 :443 结尾」判定 https，缺了它 round-trip 会把 https 报文还原成 http。
// 已知限制：https + 非默认端口（如 :8443）在 -r 导入侧仍会被还原成 http（解析器只看
// :443 这一个信号，本模块不改解析器）；复现时按 curl 行或手工改协议即可。
function hostOf(u) {
  if (u.port) return `${u.hostname}:${u.port}`;
  if (u.protocol === 'https:') return `${u.hostname}:443`;
  return u.hostname;
}

// shell 单参数引用：
//   - 常规值 → '...''...'（内部单引号替换为 '\''，bash/zsh 标准写法）
//   - 含 CR/LF 的值 → $'...\r\n...'（ANSI-C 引用：既保持单行命令，又不让换行截断命令；
//     $'' 内部 $ 与反引号同样不参与展开，只有 \ 与 ' 需转义）
// 绝不使用双引号包裹——双引号内 $()、反引号会真实执行。
export function shellQuote(value) {
  const s = String(value ?? '');
  if (s === '') return "''";
  if (/[\r\n]/.test(s)) {
    const esc = s
      .replace(/\\/g, '\\\\')
      .replace(/'/g, "\\'")
      .replace(/\r/g, '\\r')
      .replace(/\n/g, '\\n');
    return `$'${esc}'`;
  }
  return `'${s.replace(/'/g, `'\\''`)}'`;
}

// 把引擎侧的 data（对象 / 字符串）序列化成「扫描时真正落在线上的那串字节」。
// 规则与 axios 对齐（httpClient 直接把 data 交给 axios）：
//   - 字符串 → 原样（jsonBody 通道产出的 JSON 文本、HPP 之外的自定义体）
//   - 对象 + Content-Type 含 x-www-form-urlencoded → 表单编码
//   - 对象 + 无显式 Content-Type → JSON，并补上 application/json 头（axios 默认行为）
// 补头是刻意的：PoC 缺 Content-Type 时服务器可能不按 JSON 解析 → 复现结果与检测结论不符。
function serializeBody(data, headers, notes) {
  if (data == null || data === '') return '';
  if (typeof data === 'string') return data;
  if (typeof data !== 'object') return String(data);
  const entries = Object.entries(data);
  if (!entries.length) return '';
  const ct = String(headerGet(headers, 'Content-Type') || '');
  if (/x-www-form-urlencoded/i.test(ct)) {
    return new URLSearchParams(entries.map(([k, v]) => [k, v == null ? '' : String(v)])).toString();
  }
  if (!ct) {
    headers['Content-Type'] = 'application/json';
    notes.push('原请求未显式声明 Content-Type，按引擎（axios）默认语义以 application/json 序列化表单体并补该头');
  }
  // JSON 通道保留原始字段类型（injection.js 直接 JSON.stringify(jsonBody 克隆)）
  return JSON.stringify(data);
}

/**
 * 构造可复现的 PoC 请求描述。
 * @param {object} target 扫描目标（createTarget 产物：baseUrl/method/headerParams/cookieParams/jsonBody/config/mode）
 * @param {object} point  注入点（createInjectionPoint 产物：location/param/originalValue/formMethod/actionUrl/formValues）
 * @param {string} payload 命中用的 payload（通常取 vuln.payloads[0]）
 * @returns {{method:string,url:string,headers:object,body:string,note:string}} 永不抛异常
 */
export function buildPocRequest(target, point, payload) {
  const notes = [];
  const base = String((target && (target.baseUrl || target.url)) || '');
  const value = payload == null ? '' : String(payload);

  let req = null;
  try {
    // 缺少注入点上下文（历史报告 / 手工构造的 report.points 只有 id）时不去调用引擎，
    // 直接走降级分支——保证老快照也能出报告，只是 PoC 退化为基线请求。
    if (!target || !point || !point.location) throw new Error('缺少 target/point 上下文');
    req = buildInjectionRequest(target, point, value);
  } catch (e) {
    notes.push(`复用引擎注入请求失败（${e && e.message ? e.message : 'unknown'}），已降级为最小 GET 请求`);
    req = null;
  }

  // 直连模式（对标 sqlmap -d）：没有 HTTP 请求可言，SQL 语句本身就是 PoC。
  if (req && !req.url && req.sql != null) {
    return {
      method: 'SQL',
      url: '',
      headers: {},
      body: String(req.sql || ''),
      note: '直连模式无 HTTP 请求：body 即驱动直接执行的 SQL，复现请用 --db 直连或数据库客户端',
    };
  }

  // 降级：最小 GET 请求（仍带 target 的自定义头，能带就尽量可复现）。
  if (!req || !req.url) {
    const headers = {};
    try {
      for (const [k, v] of Object.entries((target && target.headerParams) || {})) headers[k] = headerValue(v);
    } catch {
      /* headerParams 异常形态：忽略，保持不抛 */
    }
    return { method: 'GET', url: base, headers, body: '', note: notes.join('；') };
  }

  const headers = {};
  for (const [k, v] of Object.entries(req.headers || {})) headers[k] = headerValue(v);
  const method = String(req.method || 'GET').toUpperCase();
  const body = serializeBody(req.data, headers, notes);

  // req.params 在引擎里恒为 {}，但为防未来新增通道，这里按 axios 语义并入 query。
  let url = String(req.url);
  const params = req.params && typeof req.params === 'object' ? req.params : {};
  const extra = Object.entries(params).filter(([, v]) => v !== undefined);
  if (extra.length) {
    const qs = new URLSearchParams(extra.map(([k, v]) => [k, String(v)])).toString();
    if (qs) url += (url.includes('?') ? '&' : '?') + qs;
  }

  if (notes.length === 0) notes.push('由引擎 buildInjectionRequest 还原，与扫描时实际请求同构');
  return { method, url, headers, body, note: notes.join('；') };
}

/**
 * 单行 curl（复制即跑）。无 URL（直连模式 / 目标缺失）时返回空串，由调用方决定文案。
 * 结构：curl -i -s -k [-X METHOD] [-H 'k: v']... '<url>' [--data '<body>']
 * 方法钉定规则：非 GET 或「GET 但带体」（--hpp 的 query+body 双份）时必须写 -X，
 * 否则 curl 一见 --data 就默默改成 POST → PoC 与扫描时的真实请求不再是同一回事。
 */
export function toCurl(req) {
  if (!req || !req.url || req.method === 'SQL') return '';
  const out = ['curl', '-i', '-s', '-k'];
  const method = String(req.method || 'GET').toUpperCase();
  const body = req.body == null ? '' : String(req.body);
  const hasBody = body !== '' && !NO_BODY_METHODS.has(method);
  if (method !== 'GET' || hasBody) out.push('-X', shellQuote(method));
  for (const [k, v] of Object.entries(req.headers || {})) {
    const name = String(k || '').trim();
    if (!name) continue;
    out.push('-H', shellQuote(`${name}: ${headerValue(v)}`));
  }
  out.push(shellQuote(req.url));
  if (hasBody) out.push('--data', shellQuote(body));
  return out.join(' ');
}

/**
 * 原始 HTTP 报文（Burp/sqlmap -r 可直接导入的格式）。
 * 与 core/requestFileParser.js#parseRequestFile 互为逆运算：
 *   请求行 `METHOD /path?query HTTP/1.1` + Header 行（含 Host）+ 空行 + body。
 * 无 URL 时返回空串（直连模式的 SQL 已在 body 字段，报告侧单独渲染）。
 */
export function toRawRequest(req) {
  if (!req || !req.url || req.method === 'SQL') return '';
  const method = String(req.method || 'GET').toUpperCase();
  let path = '/';
  try {
    const u = new URL(req.url);
    path = `${u.pathname || '/'}${u.search || ''}`;
  } catch {
    // URL 非法（例如手工传入的相对路径）：能写出请求行就写，保持不抛
    path = String(req.url).startsWith('/') ? String(req.url) : `/${String(req.url)}`;
  }
  // 请求行的请求目标里不得出现空格（已编码 payload 走拼接分支时可能漏进裸空格）：
  // 一个空格就会把请求行截成两段，整份报文无法解析（%20 与空格对服务器等价）。
  path = path.replace(/ /g, '%20');
  const lines = [`${method} ${path} HTTP/1.1`];
  let hasHost = false;
  let hasLen = false;
  for (const [k, v] of Object.entries(req.headers || {})) {
    const name = String(k || '').trim();
    if (!name) continue;
    if (name.toLowerCase() === 'host') hasHost = true;
    if (name.toLowerCase() === 'content-length') hasLen = true;
    lines.push(`${name}: ${headerValue(v)}`);
  }
  if (!hasHost) {
    try {
      lines.splice(1, 0, `Host: ${hostOf(new URL(req.url))}`);
    } catch {
      /* 无法推导 Host：交给解析侧报错，不在此处抛 */
    }
  }
  const body = req.body == null ? '' : String(req.body);
  if (body && !NO_BODY_METHODS.has(method) && !hasLen) {
    lines.push(`Content-Length: ${Buffer.byteLength(body, 'utf8')}`);
  }
  if (NO_BODY_METHODS.has(method)) return `${lines.join('\r\n')}\r\n\r\n`;
  return `${lines.join('\r\n')}\r\n\r\n${body}`;
}

/**
 * [P0-SEC 2026-09-08] 把 PoC 里的凭据头掉包（opt-in）。
 * 为什么默认不开：PoC 的价值就在「复制即跑」，登录后才能看到的注入不带 Cookie 就无法复现；
 * 而报告文件会随邮件/IM 流通，把测试者的会话凭据写进去属于自我泄露。
 * 因此开关交给部署方：config.pocRedactAuth=true 时，curl/raw/headers 三处统一打码（
 * 不能只打 headers——curl 与 raw 是从 req 生成的，先打后生成才不会漏）。
 */
const SENSITIVE_POC_HEADERS = new Set([
  'cookie',
  'set-cookie',
  'authorization',
  'proxy-authorization',
  'x-api-token',
  'x-scan-token',
  'x-api-key',
]);
export function maskSensitiveHeaders(headers) {
  const out = {};
  for (const [k, v] of Object.entries(headers || {})) {
    out[k] = SENSITIVE_POC_HEADERS.has(String(k).toLowerCase())
      ? '<已脱敏：请用你自己的会话凭据替换>'
      : v;
  }
  return out;
}

/**
 * 报告消费的完整证据对象（ReportGenerator 导出时惰性调用；检测流程不调用）。
 * @param {object} target 扫描目标
 * @param {object} point 注入点
 * @param {string} payload 确认命中的 payload
 * @param {{redactAuth?:boolean}} [opts] redactAuth=true 时凭据头统一打码（交付型报告建议开）
 * @returns {{method:string,url:string,headers:object,body:string,payload:string,curl:string,raw:string,note:string,generatedAt:string}}
 */
export function buildPocEvidence(target, point, payload, opts = {}) {
  const req = buildPocRequest(target, point, payload);
  const safeReq = opts.redactAuth === true ? { ...req, headers: maskSensitiveHeaders(req.headers) } : req;
  return {
    method: safeReq.method,
    url: safeReq.url,
    headers: safeReq.headers,
    body: safeReq.body,
    payload: payload == null ? '' : String(payload),
    curl: toCurl(safeReq),
    raw: toRawRequest(safeReq),
    note: opts.redactAuth === true ? `${safeReq.note || ''}；凭据头已按 pocRedactAuth 脱敏`.trim() : safeReq.note || '',
    generatedAt: new Date().toISOString(),
  };
}

export default buildPocEvidence;
