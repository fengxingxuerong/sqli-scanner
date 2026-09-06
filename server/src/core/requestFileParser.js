// requestFileParser.js
// 对标 sqlmap -r：解析纯文本 HTTP 请求文件（Burp 复制 / curl 保存），
// 提取 URL / method / headers / body / query params。
//
// 输入格式：
//   GET /path?id=1 HTTP/1.1
//   Host: 127.0.0.1:8123
//   User-Agent: curl/...
//   Cookie: session=abc
//
//   body=value
//
// 返回 { method, url, headers, body, params } 或 null（非法格式）。

export function parseRequestFile(text) {
  if (!text || typeof text !== 'string') return null;
  // 去除 BOM 与首尾空白
  const trimmed = text.replace(/^\uFEFF/, '').trim();
  if (!trimmed) return null;
  const lines = trimmed.split(/\r?\n/);
  if (lines.length < 1) return null;

  const first = lines[0].trim();
  // 解析请求行：METHOD /path [HTTP/1.1]（HTTP 版本可选，兼容 Burp 粘贴的无版本格式）
  const m = /^\s*(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE|CONNECT)\s+(\S+)(?:\s+HTTP\/[\d.]+)?/i.exec(first);
  if (!m) return null;
  const method = m[1].toUpperCase();
  const path = m[2];

  // 解析 headers 与 body
  const headers = {};
  let bodyStarted = false;
  const bodyParts = [];
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i];
    if (!bodyStarted && line.trim() === '') {
      bodyStarted = true;
      continue;
    }
    if (!bodyStarted) {
      const ci = line.indexOf(':');
      if (ci > 0) {
        const name = line.slice(0, ci).trim();
        const value = line.slice(ci + 1).trim();
        if (name) headers[name] = value;
      }
    } else {
      bodyParts.push(line);
    }
  }
  const body = bodyParts.join('\n').trim();

  // 构建完整 URL
  const hostKey = Object.keys(headers).find(k => k.toLowerCase() === 'host');
  let url;
  if (/^https?:\/\//i.test(path)) {
    url = path;
  } else {
    const hostVal = hostKey ? headers[hostKey] : null;
    if (!hostVal) return null; // 没有 Host 头无法构建 URL
    // [B-9a] 端口 443 默认 https，其他默认 http
    const protocol = /:443$/.test(hostVal) ? 'https' : 'http';
    url = `${protocol}://${hostVal}${path.startsWith('/') ? path : '/' + path}`;
  }

  // 提取 query params（注入参数候选）
  const params = {};
  try {
    const qIdx = url.indexOf('?');
    if (qIdx >= 0) {
      const qs = url.slice(qIdx + 1);
      for (const pair of qs.split('&')) {
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
  } catch { /* ignore decode errors */ }

  // [B-9b] 从 POST body 中提取表单参数（application/x-www-form-urlencoded）
  // 缺失此步时 POST 请求的注入参数候选遗漏
  const ctKey = Object.keys(headers).find(k => k.toLowerCase() === 'content-type');
  const ctVal = ctKey ? headers[ctKey] : '';
  if (body && ctVal && /application\/x-www-form-urlencoded/i.test(ctVal)) {
    try {
      for (const pair of body.split('&')) {
        if (!pair) continue;
        const eq = pair.indexOf('=');
        if (eq > 0) {
          const k = decodeURIComponent(pair.slice(0, eq));
          const v = decodeURIComponent(pair.slice(eq + 1));
          if (k && !(k in params)) params[k] = v;
        } else {
          const k = decodeURIComponent(pair);
          if (k && !(k in params)) params[k] = '';
        }
      }
    } catch { /* ignore decode errors */ }
  }

  return { method, url, headers, body, params };
}