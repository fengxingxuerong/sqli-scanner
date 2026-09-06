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

// ── ① 原始 HTTP 请求 ──
function detectFromRequest(text: string): DetectedTarget | null {
  const lines = text.split(/\r?\n/);
  const first = lines[0] ?? '';
  const m = /^\s*(GET|POST|PUT|PATCH|DELETE)\s+(\S+)\s+HTTP\//i.exec(first);
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
  if (/^\s*(GET|POST|PUT|PATCH|DELETE)\s+\S+\s+HTTP\//i.test(t)) return detectFromRequest(t);
  return null;
}

export function looksLikeRawRequest(input: string): boolean {
  return /^\s*(GET|POST|PUT|PATCH|DELETE)\s+\S+\s+HTTP\//i.test(input.trim());
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
  cookieText: string;
  headerText: string;
  bodyText: string;
}

export function parseRequestFile(text: string): ParsedRequest | null {
  const trimmed = (text ?? '').replace(/^\uFEFF/, '').trim();
  if (!trimmed) return null;
  const lines = trimmed.split(/\r?\n/);
  const m = /^\s*(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S+)\s+HTTP\/[\d.]+/i.exec(lines[0] ?? '');
  if (!m) return null;
  const detected = tryAutoDetect(trimmed);
  if (!detected) return null; // 缺 Host 头等 → 复用既有降级逻辑

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

  return {
    method: detected.method,
    url: detected.url,
    headers,
    body,
    params,
    cookieText: detected.cookieText,
    headerText: detected.headerText,
    bodyText: detected.bodyText,
  };
}