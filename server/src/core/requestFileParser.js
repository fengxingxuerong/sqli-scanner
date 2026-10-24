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

/**
 * [D159 拆分] 单个 multipart part 的解析（文本字段 vs 文件字段）。
 * @param {string} part 原始片段
 * @param {Record<string,string>} params 输出：字段名 → 值
 * @param {(k: string, v: string) => void} addBody 输出：bodyFields 写入器
 * @param {Array<{name: string, filename: string, contentType: string}>} fileParts 输出：文件字段
 */
function parseMultipartPart(part, params, addBody, fileParts) {
  if (!part || part.trim() === '--' || part.trim() === '') return;
  const ci = part.indexOf('\n\n');
  const head = ci >= 0 ? part.slice(0, ci) : part;
  let val = ci >= 0 ? part.slice(ci + 2) : '';
  val = val.replace(/\r?\n$/, '').replace(/^\r?\n/, '').replace(/\n+$/, '');
  const nm = /name="([^"]+)"/i.exec(head);
  if (!nm) return;
  const fn = /filename="([^"]*)"/i.exec(head);
  if (fn) {
    addMultipartFilePart(nm[1], fn[1], head, params, addBody, fileParts);
    return;
  }
  if (val && !(nm[1] in params)) params[nm[1]] = val;
  if (val) addBody(nm[1], val);
}

/**
 * [D159] 文件字段落两处：params/bodyFields（集合契约）与 fileParts（发送侧重建用）。
 * @param {string} name 字段名
 * @param {string} filename 文件名（可能为空串 —— 浏览器「未选文件」时就是这样）
 * @param {string} head part 头
 * @param {Record<string,string>} params
 * @param {(k: string, v: string) => void} addBody
 * @param {Array<{name: string, filename: string, contentType: string}>} fileParts
 */
function addMultipartFilePart(name, filename, head, params, addBody, fileParts) {
  // 文件字段：值取 filename（二进制内容无注入语义，文件名常进 SQL/日志）
  if (filename && !(name in params)) params[name] = filename;
  if (filename) addBody(name, filename);
  const ctm = /content-type:\s*([^\r\n]+)/i.exec(head);
  fileParts.push({ name, filename: filename || '', contentType: ctm ? ctm[1].trim() : '' });
}

/**
 * [D159 拆分] multipart body 字段提取（原内联在 parseRequestFile，加 fileParts 后超复杂度基线）。
 *
 * 输出两路：
 *   · 文本字段 → params（候选列表）与 bodyFields（经 addBody 回写）
 *   · 文件字段 → 返回的 fileParts（name / filename / contentType）
 * bodyFields 的契约是「body 里有哪些字段」，文件字段照收；从 bodyParams 剔除文件字段的
 * 动作在 CLI 的 applyRequestFile 里（发送侧需要按 fileParts 重建 multipart）。
 * @param {string} body 原始 body
 * @param {string} ctVal Content-Type（含 boundary）
 * @param {Record<string,string>} params 输出：字段名 → 值（就地把文本字段写入）
 * @param {(k: string, v: string) => void} addBody 输出：bodyFields 写入器
 * @returns {Array<{name: string, filename: string, contentType: string}>} 文件字段
 */
function parseMultipartFields(body, ctVal, params, addBody) {
  const fileParts = [];
  const bm = /boundary=(?:"([^"]+)"|([^;\s]+))/i.exec(ctVal);
  const boundary = bm ? (bm[1] || bm[2]) : null;
  if (!boundary) return fileParts;
  for (const part of body.split('--' + boundary)) {
    parseMultipartPart(part, params, addBody, fileParts);
  }
  return fileParts;
}

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
  /** @type {Record<string,string>} */
  const params = {};
  // [MULTIPART-R-FIX 2026-09-20] bodyFields 与 params 同步收集，但**只装来自 body 的字段**。
  // 为什么不能只给 params：它把 query、urlencoded body、multipart、JSON 四个来源混在同一个
  // 扁平对象里，调用方分不清哪个键该进 body、哪个该进 URL。以前 `-r` 导入 multipart 抓包时
  // 就是因为没处拿"纯 body 字段"，只能把原始 body 塞给 urlencoded 启发式去猜，结果整份 body
  // 塌成一个以 boundary 行命名的垃圾键（实测），扫描照跑、0 检出、无告警。
  const bodyFields = {};
  const addBody = (k, v) => { if (k && !(k in bodyFields)) bodyFields[k] = v; };
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
          addBody(k, v);
        } else {
          const k = decodeURIComponent(pair);
          if (k && !(k in params)) params[k] = '';
          addBody(k, '');
        }
      }
    } catch { /* ignore decode errors */ }
  }

  // [批次 10 2026-09-15] multipart/form-data：提取 text 字段名→值作为注入参数候选
  //（Burp 抓包上传表单常态；文件字段值取 filename 不取二进制）。只读提取，body 原样保留。
  // [D159 2026-10-25] 文件字段另收进 fileParts（实现见 parseMultipartFields）：
  // 发送侧要按 `filename=` 属性重建，不能当文本字段内容发 —— 否则目标读到的文件名恒空。
  const fileParts = body && ctVal && /multipart\/form-data/i.test(ctVal)
    ? parseMultipartFields(body, ctVal, params, addBody)
    : [];
  // [批次 10 2026-09-15] JSON body：顶层叶子值并入 params（嵌套叶子走点路径标记为候选）
  if (body && ctVal && /application\/json/i.test(ctVal)) {
    try {
      const obj = JSON.parse(body);
      const flat = (o, prefix) => {
        for (const [k, v] of Object.entries(o || {})) {
          const key = prefix ? prefix + '.' + k : k;
          if (v !== null && typeof v === 'object') flat(v, key);
          else {
            if (!(key in params)) params[key] = String(v);
            // JSON 走点路径叶子（与 params 同口径）。bodyFields 的语义是"来自 body 的注入
            // 字段候选"，不是"可直接 urlencoded 的键值"——JSON body 有自己那条通道
            // （runSingleScan 的 jsonBody），这里填它是为了让"这个 body 到底有没有字段"
            // 在三种编码下都是可答的问题，别让调用方靠 Object.keys().length 猜。
            addBody(key, String(v));
          }
        }
      };
      flat(obj, '');
    } catch { /* 非 JSON body 原样保留 */ }
  }

  // [D159] fileParts 供发送侧按真实 multipart 形态重建（filename / contentType 原样保留）
  return { method, url, headers, body, params, bodyFields, fileParts };
}