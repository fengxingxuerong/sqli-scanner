// src/shared/requestParser.ts
// 粘贴自动识别：原始 HTTP 请求 / curl 命令 → 结构化目标
// 提取自 ScanWizard.tsx，便于复用和测试

import type { MethodType } from './types';

// ── 检测结果 ──
export interface DetectedTarget {
  url: string;
  method: MethodType;
  cookieText: string;
  headerText: string;
  bodyText: string;
}

// ── 请求行首行：方法集与「HTTP 版本是否可选」──────────────────────────────
// [SERVER-PARITY 2026-09-23] 服务端权威实现在 `server/src/core/requestFileParser.js:25`：
//   /^\s*(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE|CONNECT)\s+(\S+)(?:\s+HTTP\/[\d.]+)?/i
// 前端此前**要求 HTTP 版本必填**，服务端可选 → 从 Burp 直接粘贴的「无版本」报文在 UI 上判非法、
// 引擎却扫得了（同一份粘贴文本，两端结论不同）。现已对齐「版本可选」这一条。
//
// 方法集分两套，且**都窄于服务端**，这是有意的：
//   · PARSER（7 个）：`parseRequestFile` 首行 —— 用于「请求文件导入」按钮，导入后要还原 method。
//   · DETECT（5 个）：`tryAutoDetect` / `detectFromRequest` / `looksLikeRawRequest` ——
//     它们返回 `DetectedTarget.method: MethodType`，而 `shared/types.ts` 的 MethodType 只有 5 个
//     （它同时驱动 UI 的「请求方法」下拉框）。把 TRACE/CONNECT 塞进 MethodType 会让用户能
//     选一个「扫不出注入且不该由本工具发」的方法，代价远大于收益。
//   服务端多出的 TRACE / CONNECT 因此**有意不支持**，前端是服务端的子集 ——
//   这个差异由 src/tests/requestParser.serverParity.test.ts 登记并守卫（任一侧改动都会红）。
export const REQUEST_LINE_METHODS_PARSER = [
  'GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS',
] as const;
export const REQUEST_LINE_METHODS_DETECT = [
  'GET', 'POST', 'PUT', 'PATCH', 'DELETE',
] as const;
/** HTTP 版本可选：兼容 Burp 等抓包工具粘贴出的无版本请求行 */
const RE_BUILD = (methods: readonly string[]) =>
  new RegExp(`^\\s*(${methods.join('|')})\\s+(\\S+)(?:\\s+HTTP\\/[\\d.]+)?`, 'i');
const RE_PARSER = RE_BUILD(REQUEST_LINE_METHODS_PARSER);
const RE_DETECT = RE_BUILD(REQUEST_LINE_METHODS_DETECT);

// ── 常见浏览器噪声请求头（自动识别时剔除） ──
const NOISE_HEADERS = [
  'host', 'content-length', 'accept', 'accept-encoding', 'accept-language',
  'connection', 'user-agent', 'cookie', 'origin', 'referer', 'pragma',
  'cache-control', 'upgrade-insecure-requests', 'te', 'dnt',
];

function isNoiseHeader(name: string): boolean {
  const n = name.toLowerCase();
  return NOISE_HEADERS.includes(n) || n.startsWith('sec-');
}

// ── 文本转 JSON ──
function toJsonText(text: string): string {
  const t = text.trim();
  if (!t) return '';
  try {
    return JSON.stringify(JSON.parse(t), null, 2);
  } catch {
    if (t.includes('=') && !t.includes('{')) {
      const out: Record<string, string> = {};
      for (const pair of t.split('&')) {
        const idx = pair.indexOf('=');
        if (idx > 0) {
          const k = decodeURIComponent(pair.slice(0, idx));
          const v = decodeURIComponent(pair.slice(idx + 1));
          if (k) out[k] = v;
        }
      }
      if (Object.keys(out).length) return JSON.stringify(out, null, 2);
    }
    return t;
  }
}

// ── 解析 Cookie 串 ──
function parseCookiePairs(cookieStr: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const pair of cookieStr.split(';')) {
    const idx = pair.indexOf('=');
    if (idx > 0) {
      const k = pair.slice(0, idx).trim();
      const v = pair.slice(idx + 1).trim();
      if (k) out[k] = v;
    }
  }
  return out;
}

// ── 从 body 提取注入字段候选（与 server/src/core/requestFileParser.js 同口径） ──
// 为什么需要它：params 把 query / urlencoded / multipart / JSON 四个来源混在同一个扁平
// 对象里，调用方分不清哪个键来自 body、该走哪条通道。bodyFields 只装 body 来源的字段。
//
// 四种编码的差异都要认：
//   · urlencoded  : k=v&k2=v2
//   · multipart   : 文本字段取值；**文件字段取 filename**（二进制无注入语义，文件名常进 SQL/日志）
//   · JSON        : 顶层叶子 + 嵌套叶子走点路径
//   · 其它        : 不猜（旧版对任意含 '=' 的 body 套 urlencoded 启发式，会把 multipart 报文
//                  整份塌成一个以 boundary 行命名的垃圾键）
export interface BodyFieldExtraction {
  params: Record<string, string>; // 与 query 合并后的全量候选（query 优先，不被 body 覆盖）
  bodyFields: Record<string, string>; // 仅来自 body 的字段
}

export function extractBodyFields(
  body: string,
  contentType: string,
  params: Record<string, string>,
): BodyFieldExtraction {
  const addBody = (k: string, v: string) => {
    if (k && !(k in bodyFields)) bodyFields[k] = v;
  };
  const bodyFields: Record<string, string> = {};
  if (!body) return { params, bodyFields };
  const ct = contentType || '';

  if (/application\/x-www-form-urlencoded/i.test(ct)) {
    try {
      for (const pair of body.split('&')) {
        if (!pair) continue;
        const eq = pair.indexOf('=');
        if (eq > 0) {
          const k = decodeURIComponent(pair.slice(0, eq));
          const v = decodeURIComponent(pair.slice(eq + 1));
          if (k && !(k in params)) params[k] = v;
          addBody(k, v);
        } else {
          const k = decodeURIComponent(pair);
          if (k && !(k in params)) params[k] = '';
          addBody(k, '');
        }
      }
    } catch { /* 解码失败忽略 */ }
    return { params, bodyFields };
  }

  if (/multipart\/form-data/i.test(ct)) {
    const bm = /boundary=(?:"([^"]+)"|([^;\s]+))/i.exec(ct);
    const boundary = bm ? (bm[1] || bm[2]) : null;
    if (boundary) {
      const parts = body.split('--' + boundary);
      for (const part of parts) {
        if (!part || part.trim() === '--' || part.trim() === '') continue;
        const ci = part.indexOf('\n\n');
        const head = ci >= 0 ? part.slice(0, ci) : part;
        let val = ci >= 0 ? part.slice(ci + 2) : '';
        val = val.replace(/\r?\n$/, '').replace(/^\r?\n/, '').replace(/\n+$/, '');
        const nm = /name="([^"]+)"/i.exec(head);
        if (!nm) continue;
        const fn = /filename="([^"]*)"/i.exec(head);
        if (fn) {
          if (fn[1] && !(nm[1] in params)) params[nm[1]] = fn[1];
          if (fn[1]) addBody(nm[1], fn[1]);
          continue;
        }
        if (val && !(nm[1] in params)) params[nm[1]] = val;
        if (val) addBody(nm[1], val);
      }
    }
    return { params, bodyFields };
  }

  if (/application\/json/i.test(ct)) {
    try {
      const obj = JSON.parse(body);
      const flat = (o: unknown, prefix: string) => {
        for (const [k, v] of Object.entries((o ?? {}) as Record<string, unknown>)) {
          const key = prefix ? prefix + '.' + k : k;
          if (v !== null && typeof v === 'object') flat(v, key);
          else {
            if (!(key in params)) params[key] = String(v);
            addBody(key, String(v));
          }
        }
      };
      flat(obj, '');
    } catch { /* 非 JSON body 原样保留 */ }
  }
  return { params, bodyFields };
}

// ── ① 原始 HTTP 请求 ──
function detectFromRequest(text: string): DetectedTarget | null {
  const lines = text.split(/\r?\n/);
  const first = lines[0] ?? '';
  const m = RE_DETECT.exec(first);
  if (!m) return null;
  const method = m[1].toUpperCase() as MethodType;
  let target = m[2];
  const headers: Record<string, string> = {};
  const cookies: Record<string, string> = {};
  let body = '';
  let bodyStarted = false;
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i];
    if (!bodyStarted && line.trim() === '') { bodyStarted = true; continue; }
    if (!bodyStarted) {
      const ci = line.indexOf(':');
      if (ci > 0) {
        const name = line.slice(0, ci).trim();
        const value = line.slice(ci + 1).trim();
        if (name.toLowerCase() === 'cookie') Object.assign(cookies, parseCookiePairs(value));
        else if (!isNoiseHeader(name)) headers[name] = value;
      }
    } else { body += (body ? '\n' : '') + line; }
  }
  if (!/^https?:\/\//i.test(target)) {
    const host = lines.find((l) => /^host:/i.test(l))?.slice(5).trim();
    if (!host) return null;
    target = `http://${host}${target.startsWith('/') ? target : '/' + target}`;
  }
  return {
    url: target, method,
    cookieText: Object.keys(cookies).length ? JSON.stringify(cookies, null, 2) : '',
    headerText: Object.keys(headers).length ? JSON.stringify(headers, null, 2) : '',
    bodyText: toJsonText(body),
  };
}

// ── ② curl 命令 ──
function detectFromCurl(text: string): DetectedTarget | null {
  const t = text.trim();
  if (!/^curl\b/i.test(t)) return null;
  let method: MethodType = 'GET';
  const urlM = /https?:\/\/[^\s'")]+/.exec(t);
  if (!urlM) return null;
  const url = urlM[0].replace(/[;,)'"]+$/g, '');
  const xm = /(?:^|\s)-X\s+([A-Z]+)/i.exec(t);
  if (xm) method = xm[1].toUpperCase() as MethodType;
  const headers: Record<string, string> = {};
  const cookies: Record<string, string> = {};
  const headerRe = /(?:^|\s)-H\s+(?:'([^']*)'|"([^"]*)")/g;
  let hm: RegExpExecArray | null;
  while ((hm = headerRe.exec(t))) {
    const raw = hm[1] ?? hm[2] ?? '';
    const ci = raw.indexOf(':');
    if (ci <= 0) continue;
    const name = raw.slice(0, ci).trim();
    const value = raw.slice(ci + 1).trim();
    if (name.toLowerCase() === 'cookie') Object.assign(cookies, parseCookiePairs(value));
    else if (!isNoiseHeader(name)) headers[name] = value;
  }
  const bm = /(?:^|\s)(?:-b|--cookie)\s+(?:'([^']*)'|"([^"]*)")/i.exec(t);
  if (bm) Object.assign(cookies, parseCookiePairs(bm[1] ?? bm[2] ?? ''));
  let body = '';
  const dataRe = /(?:^|\s)(?:--data-raw|--data|-d)\s+(?:'([^']*)'|"([^"]*)")/i.exec(t);
  if (dataRe) { body = dataRe[1] ?? dataRe[2] ?? ''; if (method === 'GET') method = 'POST'; }
  return {
    url, method,
    cookieText: Object.keys(cookies).length ? JSON.stringify(cookies, null, 2) : '',
    headerText: Object.keys(headers).length ? JSON.stringify(headers, null, 2) : '',
    bodyText: toJsonText(body),
  };
}

// ── 统一入口 ──
export function tryAutoDetect(input: string): DetectedTarget | null {
  const t = input.trim();
  if (!t) return null;
  if (/^curl\b/i.test(t)) return detectFromCurl(t);
  if (RE_DETECT.test(t)) return detectFromRequest(t);
  return null;
}

export function looksLikeRawRequest(input: string): boolean {
  return RE_DETECT.test(input.trim());
}

// ── 对标 sqlmap -r：解析完整 HTTP 请求文本 → 结构化目标 ──
// 与 tryAutoDetect 的区别：本函数面向「请求文件导入」按钮，
// 返回结构化 { method, url, headers, body, params }（params=URL query 注入候选），
// 同时附带 form-ready 的 cookieText/headerText/bodyText 便于直接填充表单。
export interface ParsedRequest {
  method: MethodType;
  url: string;
  headers: Record<string, string>;
  body: string;
  params: Record<string, string>;
  /** 仅来自 body 的注入字段（区别于 params 里混入的 query 来源） */
  bodyFields: Record<string, string>;
  cookieText: string;
  headerText: string;
  bodyText: string;
}

export function parseRequestFile(text: string): ParsedRequest | null {
  const trimmed = (text ?? '').replace(/^\uFEFF/, '').trim();
  if (!trimmed) return null;
  const lines = trimmed.split(/\r?\n/);
  const m = RE_PARSER.exec(lines[0] ?? '');
  if (!m) return null;
  const detected = tryAutoDetect(trimmed);
  if (!detected) return null; // 缺 Host 头、或方法在 DETECT 集之外（HEAD/OPTIONS/TRACE/CONNECT）→ 沿用既有降级逻辑

  // 提取 query params（注入候选）
  const params: Record<string, string> = {};
  try {
    const qIdx = detected.url.indexOf('?');
    if (qIdx >= 0) {
      for (const pair of detected.url.slice(qIdx + 1).split('&')) {
        if (!pair) continue;
        const eq = pair.indexOf('=');
        if (eq > 0) {
          const k = decodeURIComponent(pair.slice(0, eq));
          const v = decodeURIComponent(pair.slice(eq + 1));
          if (k) params[k] = v;
        } else {
          params[decodeURIComponent(pair)] = '';
        }
      }
    }
  } catch { /* ignore */ }

  // 从原始文本提取 headers 与 body（结构化，不剔除噪声头，供导入后完整还原）
  const headers: Record<string, string> = {};
  const cookies: Record<string, string> = {};
  let body = '';
  let bodyStarted = false;
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i];
    if (!bodyStarted && line.trim() === '') { bodyStarted = true; continue; }
    if (!bodyStarted) {
      const ci = line.indexOf(':');
      if (ci > 0) {
        const name = line.slice(0, ci).trim();
        const value = line.slice(ci + 1).trim();
        if (name.toLowerCase() === 'cookie') Object.assign(cookies, parseCookiePairs(value));
        else headers[name] = value;
      }
    } else {
      body += (body ? '\n' : '') + line;
    }
  }
  body = body.trim();

  // body 编码分派：multipart / JSON / urlencoded 三种来源各自提取注入字段。
  // params 已在上面装了 query 候选，这里把 body 来源的字段并进来（query 优先）。
  const ctKey = Object.keys(headers).find((k) => k.toLowerCase() === 'content-type');
  const ctVal = ctKey ? headers[ctKey] : '';
  const { bodyFields } = extractBodyFields(body, ctVal, params);

  // bodyText 是给表单 body 编辑器用的「可读结构化文本」。multipart 报文不能被
  // toJsonText 的 `=` 启发式处理（会把整份报文塌成一个垃圾键），因此这里按编码分派：
  //   · multipart → 用提取出的 bodyFields 重建 JSON（文件字段标出 filename 形态）
  //   · 其它       → 维持既有 toJsonText 行为（urlencoded / JSON / 原样）
  const isMultipart = /multipart\/form-data/i.test(ctVal);
  const bodyText = isMultipart && Object.keys(bodyFields).length
    ? JSON.stringify(bodyFields, null, 2)
    : toJsonText(body);

  return {
    method: detected.method,
    url: detected.url,
    headers,
    body,
    params,
    bodyFields,
    cookieText: detected.cookieText,
    headerText: detected.headerText,
    bodyText,
  };
}