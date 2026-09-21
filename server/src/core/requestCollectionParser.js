// ============================================================================
// requestCollectionParser.js —— 抓包/导出**集合**格式 → 原始 HTTP 报文
// ============================================================================
// 为什么需要它：`-r` 原先只认「单个 Burp/curl 文本请求」（requestFileParser）。
// 而实战交付的起点常常是**集合**：Burp 的 XML 导出、浏览器 F12 / Charles 的 HAR。
// 直接抛「需为 Burp/curl 文本 HTTP 请求格式」会让人第一步就卡住。
//
// ★核心设计：**不重写解析逻辑**。
//   本模块只做「集合格式 → 原始 HTTP 报文文本」这一层归一化，随后**一律交给
//   requestFileParser.parseRequestFile** 解析。收益：
//     · 返回契约与单请求路径**完全一致**（method/url/headers/body/params/bodyFields）；
//     · multipart「整份 body 塌成一个垃圾键」、JSON 点路径叶子、urlencoded bodyFields
//       这些**已经踩过坑才修好**的逻辑自动继承，不会在新格式上二次犯错。
//
// 已支持：Burp Suite XML（<items><item>，request 可 base64）、HAR 1.2、
//         Postman Collection v2.x（item 可嵌套）、OpenAPI 3.x / Swagger 2.0（JSON）。
// 不支持：OpenAPI 的 YAML 形式（本模块不引 YAML 依赖，会给出转换指引）、非 Burp 的 XML。
//
// 诚实口径：解析失败**不抛异常**，返回 { format, requests: [], warnings: [] }，
//   由调用方决定如何提示 —— 不给"静默返回空"留机会。
// ============================================================================
import { parseRequestFile } from './requestFileParser.js';

/** 集合格式识别。返回 'har' | 'burp-xml' | 'postman' | 'openapi' | 'openapi-yaml' | 'unsupported' | 'raw' */
export function detectRequestFormat(text) {
  if (!text || typeof text !== 'string') return null;
  const head = text.replace(/^\uFEFF/, '').trimStart();

  // OpenAPI 常以 YAML 形式流通（`openapi: 3.0.0`）。本模块**不引 YAML 依赖**（server 侧未装 yaml，
  // 装了也会把依赖面扩大），故只给出可操作提示，而不是让它落到 raw 分支报"不是合法请求文本"。
  if (/^[\s#-]*(openapi|swagger)\s*:/im.test(head) && !head.startsWith('{')) return 'openapi-yaml';

  // XML 家族：<items> 是 Burp 导出；其它 XML 明确报 unsupported，不猜
  if (head.startsWith('<')) {
    if (/<items[\s>]/i.test(text) && /<item[\s>]/i.test(text)) return 'burp-xml';
    return 'unsupported';
  }

  if (head.startsWith('{') || head.startsWith('[')) {
    let obj;
    try {
      obj = JSON.parse(text);
    } catch {
      return 'raw'; // 不是合法 JSON：交给单请求解析器处理（它自己会判非法）
    }
    if (obj && typeof obj === 'object') {
      if (obj.log && Array.isArray(obj.log.entries)) return 'har';
      // Postman Collection v2.x：顶层 { info, item[] }；item 可嵌套（folder）→ 解析时递归展开
      if (Array.isArray(obj.item)) return 'postman';
      // OpenAPI 3.x / Swagger 2.0（JSON 形式）
      if (obj.openapi || obj.swagger) return 'openapi';
    }
    return 'raw';
  }

  return 'raw';
}

/**
 * 极简原始报文重建（请求行 + Host + 空行 + body）。
 * 不复用 `engine/pocBuilder.js#toRawRequest`：core → engine 是反向层次依赖，
 * 会破坏 arch-guard 的分层约定。两者职责相同、都很短，此处本地实现并显式记录取舍；
 * 若将来 core 层允许依赖 engine，应当合并为一处。
 */
function buildRawRequest({ method, url, headers, body }) {
  const m = String(method || 'GET').toUpperCase();
  let path = '/';
  let host = '';
  try {
    const u = new URL(url);
    path = `${u.pathname || '/'}${u.search || ''}`;
    host = u.host;
  } catch {
    path = String(url || '/');
  }
  path = path.replace(/ /g, '%20'); // 请求行里不得出现裸空格（会截断整份报文）
  const lines = [`${m} ${path} HTTP/1.1`];
  const hdrs = { ...(headers || {}) };
  const hostKey = Object.keys(hdrs).find((k) => k.toLowerCase() === 'host');
  if (hostKey) delete hdrs[hostKey];
  if (host) lines.push(`Host: ${host}`);
  for (const [k, v] of Object.entries(hdrs)) {
    if (!k) continue;
    lines.push(`${k}: ${v == null ? '' : String(v)}`);
  }
  const b = body == null ? '' : String(body);
  return `${lines.join('\r\n')}\r\n\r\n${b}`;
}

/** 把「原始报文」解析成标准契约；失败返回 null（调用方计入 warnings） */
function toRequest(rawText) {
  return parseRequestFile(rawText);
}

/** HAR 1.2：log.entries[].request */
function parseHar(obj) {
  const requests = [];
  const warnings = [];
  const entries = obj?.log?.entries;
  if (!Array.isArray(entries)) return { requests, warnings: ['HAR 缺少 log.entries 数组'] };

  entries.forEach((entry, i) => {
    const r = entry?.request;
    if (!r || !r.url) {
      warnings.push(`第 ${i + 1} 个 entry 无 request.url，已跳过`);
      return;
    }
    // headers 在 HAR 里是 [{name,value}] 数组（可能有重复名，后者覆盖前者 —— 与浏览器行为一致）
    const headers = {};
    for (const h of r.headers || []) {
      if (h && h.name) headers[h.name] = h.value == null ? '' : String(h.value);
    }
    let body = r.postData?.text;
    if (body != null && r.postData?.encoding === 'base64') {
      try {
        body = Buffer.from(String(body), 'base64').toString('utf8');
      } catch {
        warnings.push(`第 ${i + 1} 个 entry 的 postData 标注 base64 但解码失败，已按原文处理`);
      }
    }
    const raw = buildRawRequest({ method: r.method, url: r.url, headers, body });
    const parsed = toRequest(raw);
    if (!parsed) {
      warnings.push(`第 ${i + 1} 个 entry 解析失败（url=${r.url}）`);
      return;
    }
    requests.push({ ...parsed, label: `${r.method || 'GET'} ${r.url}` });
  });
  return { requests, warnings };
}

/**
 * Burp Suite XML 导出：<items><item>…<request base64="true">…</request>…</item></items>
 * 取 `<request>` 块直接用（它就是原始报文）；缺失时用 `<method>`/`<url>` 兜底。
 * 用字符串切分而非 XML 库：仓库无 XML 依赖，且 Burp 该结构固定、可控；
 * 解析不出的 item 计入 warnings 而不是静默丢弃。
 */
function parseBurpXml(text) {
  const requests = [];
  const warnings = [];
  const blocks = text.split(/<item[\s>]/i).slice(1);
  if (!blocks.length) return { requests, warnings: ['未找到 <item> 节点（Burp 导出应为 <items><item>…）'] };

  blocks.forEach((block, i) => {
    const body0 = block.split(/<\/item>/i)[0];
    const reqMatch = /<request([^>]*)>([\s\S]*?)<\/request>/i.exec(body0);
    let raw = null;
    let label = '';
    const urlM = /<url>([\s\S]*?)<\/url>/i.exec(body0);
    const url = urlM ? stripCdata(urlM[1]).trim() : '';
    const methodM = /<method>([\s\S]*?)<\/method>/i.exec(body0);
    const method = methodM ? stripCdata(methodM[1]).trim() : 'GET';
    label = `${method} ${url}`.trim();

    // ⚠️ scheme 判定必须看 `<url>` 元素，不能看重建后的报文：报文只有请求行 + Host，
    // 没有 scheme，重建时会默认成 http —— 于是 `ftp://host/x` 会"变成" http://host/x，
    // 把「非 http(s) 跳过」这条既有语义静默破坏（本文件首版即如此，被 cli.log.test.js
    // 的既有用例与新增用例同时抓到）。此处显式跳过并留 warning。
    if (url && !/^https?:\/\//i.test(url)) {
      warnings.push(`第 ${i + 1} 个 item 的 <url> 非 http(s)，已跳过：${url}`);
      return;
    }

    if (reqMatch) {
      const attrs = reqMatch[1] || '';
      let content = reqMatch[2] || '';
      const isBase64 = /base64\s*=\s*"true"/i.test(attrs);
      if (isBase64) {
        try {
          // ⚠️ 必须先剥 CDATA 再解码：部分 Burp 版本/第三方导出会把 base64 写成
          // `<request base64="true"><![CDATA[BASE64…]]></request>`，直接解码拿到的是
          // 含 "<![CDATA[" 前缀的乱码 → 报文解析必失败（本文件首版即踩此坑，
          // 被单测「base64 解码」「POST body 参数」「多 item 保序」三条用例同时抓到）。
          const b64 = stripCdata(content).replace(/\s+/g, '');
          content = Buffer.from(b64, 'base64').toString('utf8');
        } catch {
          warnings.push(`第 ${i + 1} 个 item 的 request 标注 base64 但解码失败`);
          return;
        }
      } else {
        content = stripCdata(content);
      }
      raw = content.replace(/\r\n/g, '\n').replace(/\n/g, '\r\n').trimEnd();
    } else if (url) {
      // 兜底：只有 url/method（如手工整理的清单）——构造无 body 的报文
      warnings.push(`第 ${i + 1} 个 item 无 <request>，已用 <method>/<url> 兜底构造`);
      raw = buildRawRequest({ method, url, headers: {}, body: '' });
    } else {
      warnings.push(`第 ${i + 1} 个 item 既无 <request> 也无 <url>，已跳过`);
      return;
    }

    const parsed = toRequest(raw);
    if (!parsed) {
      warnings.push(`第 ${i + 1} 个 item 报文解析失败长度=${String(raw).length}`);
      return;
    }
    // `<url>` 元素是**权威 URL**（带 scheme），用它校正报文重建的结果：
    // 报文只有请求行 + Host，而 parseRequestFile 靠「Host 是否以 :443 结尾」判协议
    // （requestFileParser.js [B-9a]），Burp 的 Host 是裸域名 ⇒ https 目标会被降级成 http。
    // 实测该差异被 cli.log.test.js 既有用例抓到（期望 https、实际 http）。
    if (url && /^https?:\/\//i.test(url)) parsed.url = url;
    requests.push({ ...parsed, label });
  });
  return { requests, warnings };
}

function stripCdata(s) {
  const m = /^\s*<!\[CDATA\[([\s\S]*?)\]\]>\s*$/.exec(s);
  return m ? m[1] : s;
}

/** Postman 变量占位（{{baseUrl}} 等）：无法求值 → 跳过并提示，而不是拼出一个坏 URL */
const HAS_POSTMAN_VAR = /\{\{[^}]+\}\}/;

/** Postman Collection v2.x：{ info, item[] }；item 可嵌套（folder）需递归展开 */
function parsePostman(obj) {
  const requests = [];
  const warnings = [];
  const urlOf = (u) => {
    if (typeof u === 'string') return u;
    if (!u || typeof u !== 'object') return '';
    if (u.raw) return String(u.raw);
    const host = Array.isArray(u.host) ? u.host.join('.') : String(u.host || '');
    if (!host) return '';
    const path = Array.isArray(u.path) ? u.path.join('/') : String(u.path || '');
    const q = (u.query || []).filter((x) => x && x.key).map((x) => `${x.key}=${x.value ?? ''}`).join('&');
    return `${u.protocol || 'http'}://${host}${path ? '/' + path : ''}${q ? '?' + q : ''}`;
  };

  const walk = (items) => {
    for (const it of items || []) {
      if (!it || typeof it !== 'object') continue;
      if (Array.isArray(it.item)) { walk(it.item); continue; } // folder → 递归
      const r = it.request;
      if (!r || typeof r !== 'object') continue;
      const name = it.name ? `「${it.name}」` : '';
      const url = urlOf(r.url);
      if (!url) { warnings.push(`第 ${requests.length + 1} 个 item${name} 无可用 URL，已跳过`); continue; }
      if (HAS_POSTMAN_VAR.test(url)) {
        warnings.push(`item${name} 的 URL 含 Postman 变量（{{…}}）：${url.slice(0, 80)} —— 请先在 Postman 里替换变量后重新导出`);
        continue;
      }
      const headers = {};
      for (const h of r.header || []) {
        if (h && h.key && h.disabled !== true) headers[h.key] = h.value == null ? '' : String(h.value);
      }
      // body：四种 mode 归一化成"报文里的 body + 必要 Content-Type"
      let body = '';
      const b = r.body || {};
      const hasCt = Object.keys(headers).some((k) => /^content-type$/i.test(k));
      if (b.mode === 'raw') {
        body = String(b.raw ?? '');
      } else if (b.mode === 'urlencoded') {
        const pairs = (b.urlencoded || []).filter((x) => x && x.key && x.disabled !== true);
        body = pairs.map((x) => `${x.key}=${x.value ?? ''}`).join('&');
        if (!hasCt) headers['Content-Type'] = 'application/x-www-form-urlencoded';
      } else if (b.mode === 'formdata') {
        // 构造真实 multipart 报文（boundary + Content-Disposition），这样能复用
        // requestFileParser 的 multipart 提取 → bodyFields 拿到真实字段名而不是一个垃圾键
        const boundary = `----PostmanBoundary${Math.random().toString(36).slice(2, 10)}`;
        const chunks = [];
        for (const f of b.formdata || []) {
          if (!f || !f.key || f.disabled === true) continue;
          if (f.type === 'file') {
            const fn = String(f.src || 'file.bin').split(/[\\/]/).pop() || 'file.bin';
            chunks.push(
              `--${boundary}\r\nContent-Disposition: form-data; name="${f.key}"; filename="${fn}"\r\nContent-Type: application/octet-stream\r\n\r\n`
            );
          } else {
            chunks.push(`--${boundary}\r\nContent-Disposition: form-data; name="${f.key}"\r\n\r\n${f.value ?? ''}\r\n`);
          }
        }
        chunks.push(`--${boundary}--\r\n`);
        body = chunks.join('');
        headers['Content-Type'] = `multipart/form-data; boundary=${boundary}`;
      } else if (b.mode === 'graphql') {
        body = JSON.stringify({ query: b.graphql?.query || '', variables: safeJson(b.graphql?.variables) });
        if (!hasCt) headers['Content-Type'] = 'application/json';
      } else if (b.mode) {
        warnings.push(`item${name} 的 body.mode=${b.mode} 暂不支持，已按无 body 处理`);
      }

      const parsed = toRequest(buildRawRequest({ method: r.method, url, headers, body }));
      if (!parsed) { warnings.push(`item${name} 报文解析失败（url=${url.slice(0, 80)}）`); continue; }
      if (/^https?:\/\//i.test(url)) parsed.url = url; // Postman 的 url.raw 是权威值（含正确 scheme）
      requests.push({ ...parsed, label: `${String(r.method || 'GET').toUpperCase()} ${url}` });
    }
  };

  walk(obj.item);
  if (!requests.length && !warnings.length) warnings.push('Postman 集合里没有可解析的请求（item 为空？）');
  return { requests, warnings };
}

function safeJson(s) {
  if (s == null || s === '') return undefined;
  if (typeof s === 'object') return s;
  try { return JSON.parse(String(s)); } catch { return undefined; }
}

/** 从 parameter/schema 推一个样例值：有 example 用 example，否则按类型给可注入的占位 */
function sampleValue(prm) {
  const ex = prm.example ?? prm.schema?.example ?? prm.schema?.default;
  if (ex !== undefined && ex !== null) return String(ex);
  if (Array.isArray(prm.schema?.enum) && prm.schema.enum.length) return String(prm.schema.enum[0]);
  const t = prm.schema?.type;
  if (t === 'boolean') return 'true';
  // 数字/字符串统一给 '1'：数字形态在真实 SQL 里最可能被直接拼接，注入点更贴近实际
  return '1';
}

/** 递归从 JSON Schema 造样例（深度封顶，避免自引用 schema 打转） */
function schemaExample(schema, depth = 0) {
  if (!schema || typeof schema !== 'object' || depth > 3) return null;
  if (schema.example !== undefined) return schema.example;
  if (Array.isArray(schema.enum) && schema.enum.length) return schema.enum[0];
  if (schema.type === 'object' || schema.properties) {
    const o = {};
    for (const [k, v] of Object.entries(schema.properties || {})) o[k] = schemaExample(v, depth + 1) ?? '1';
    return o;
  }
  if (schema.type === 'array') return [schemaExample(schema.items, depth + 1) ?? '1'];
  if (schema.type === 'integer' || schema.type === 'number') return 1;
  if (schema.type === 'boolean') return true;
  return '1';
}

/**
 * OpenAPI 3.x / Swagger 2.0（JSON 形式）→ 样例请求集合。
 * ⚠️ 与 HAR/Burp 有**本质区别**：接口定义不是抓包，参数值来自 example/default，
 * 缺失处用占位值。因此输出**必然带一条警示 warning**，不做"看起来像真请求"的伪装。
 */
function parseOpenApi(obj) {
  const requests = [];
  const warnings = [];
  const base = obj.servers?.[0]?.url
    || (obj.host ? `${(obj.schemes && obj.schemes[0]) || 'http'}://${obj.host}${obj.basePath || ''}` : '');
  if (!base) {
    warnings.push('OpenAPI 未声明 servers[0].url（Swagger 2.0 需 host/basePath）→ 无法拼出目标地址');
    return { requests, warnings };
  }
  const METHODS = ['get', 'post', 'put', 'patch', 'delete'];
  for (const [rawPath, item] of Object.entries(obj.paths || {})) {
    if (!item || typeof item !== 'object') continue;
    for (const m of METHODS) {
      const op = item[m];
      if (!op || typeof op !== 'object') continue;
      let path = rawPath;
      const query = [];
      const headers = {};
      for (const prm of [...(item.parameters || []), ...(op.parameters || [])]) {
        if (!prm || !prm.name) continue;
        const val = sampleValue(prm);
        if (prm.in === 'path') path = path.replace(`{${prm.name}}`, encodeURIComponent(val));
        else if (prm.in === 'query') query.push(`${prm.name}=${encodeURIComponent(val)}`);
        else if (prm.in === 'header') headers[prm.name] = val;
      }
      let body = '';
      const content = op.requestBody?.content;
      if (content) {
        const [ct, media] = Object.entries(content)[0] || [];
        if (ct) {
          headers['Content-Type'] = ct;
          const ex = media?.example ?? schemaExample(media?.schema);
          body = typeof ex === 'string' ? ex : JSON.stringify(ex ?? {});
        }
      }
      const url = base.replace(/\/+$/, '') + (path.startsWith('/') ? path : '/' + path)
        + (query.length ? '?' + query.join('&') : '');
      const parsed = toRequest(buildRawRequest({ method: m.toUpperCase(), url, headers, body }));
      if (!parsed) { warnings.push(`${m.toUpperCase()} ${rawPath} 报文解析失败`); continue; }
      parsed.url = url;
      requests.push({ ...parsed, label: `${m.toUpperCase()} ${url}` });
    }
  }
  if (requests.length) {
    warnings.push(
      `OpenAPI 是**接口定义**而非抓包：参数值取自 example/default，缺失处用占位 '1' —— ` +
      `共推导 ${requests.length} 个样例请求，实际参数需自行核对后再扫`
    );
  } else {
    warnings.push('OpenAPI 未展开出任何请求（paths 为空？或方法不在 GET/POST/PUT/PATCH/DELETE 内）');
  }
  return { requests, warnings };
}

/**
 * 统一入口：识别格式 → 归一化成原始报文 → parseRequestFile。
 * @returns {{format: string|null, requests: Array<object>, warnings: string[]}}
 */
export function parseRequestCollection(text) {
  const format = detectRequestFormat(text);
  if (!format) return { format, requests: [], warnings: ['内容为空'] };

  if (format === 'har') {
    let obj;
    try {
      obj = JSON.parse(text);
    } catch (e) {
      return { format, requests: [], warnings: [`HAR JSON 解析失败：${e.message}`] };
    }
    return { format, ...parseHar(obj) };
  }

  if (format === 'burp-xml') return { format, ...parseBurpXml(text) };

  if (format === 'postman' || format === 'openapi') {
    let obj;
    try {
      obj = JSON.parse(text);
    } catch (e) {
      return { format, requests: [], warnings: [`${format === 'postman' ? 'Postman' : 'OpenAPI'} JSON 解析失败：${e.message}`] };
    }
    return { format, ...(format === 'postman' ? parsePostman(obj) : parseOpenApi(obj)) };
  }

  if (format === 'openapi-yaml') {
    return {
      format,
      requests: [],
      warnings: [
        '识别为 OpenAPI/Swagger 的 **YAML** 形式。本工具不引 YAML 依赖（只在 server 侧跑，'
          + '装 yaml 会扩大依赖面）→ 请转成 JSON 后重试：'
          + 'Swagger Editor 里 File → Convert and save as JSON，或 `python -c "import yaml,json,sys;json.dump(yaml.safe_load(open(sys.argv[1])),open(sys.argv[2],\'w\'))" in.yaml out.json`',
      ],
    };
  }

  if (format === 'unsupported') {
    return {
      format,
      requests: [],
      warnings: [
        '识别为暂不支持的格式（非 Burp 的 XML）。当前支持：Burp XML 导出、HAR、'
          + 'Postman Collection、OpenAPI/Swagger（JSON）；或直接给单个 Burp/curl 文本请求。',
      ],
    };
  }

  // raw：单请求文本，保持既有行为
  const parsed = toRequest(text);
  return {
    format: 'raw',
    requests: parsed ? [{ ...parsed, label: `${parsed.method} ${parsed.url}` }] : [],
    warnings: parsed ? [] : ['不是合法的原始 HTTP 请求文本（缺少请求行或 Host）'],
  };
}
