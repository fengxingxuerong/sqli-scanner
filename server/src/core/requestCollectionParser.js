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
// 已支持：Burp Suite XML（<items><item>，request 可 base64）、HAR 1.2。
// 暂不支持（二期）：Postman Collection、OpenAPI/Swagger（会明确返回 unsupported）。
//
// 诚实口径：解析失败**不抛异常**，返回 { format, requests: [], warnings: [] }，
//   由调用方决定如何提示 —— 不给"静默返回空"留机会。
// ============================================================================
import { parseRequestFile } from './requestFileParser.js';

/** 集合格式识别。返回 'har' | 'burp-xml' | 'unsupported' | 'raw'（raw = 单请求文本） */
export function detectRequestFormat(text) {
  if (!text || typeof text !== 'string') return null;
  const head = text.replace(/^\uFEFF/, '').trimStart();

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
    if (obj && typeof obj === 'object' && obj.log && Array.isArray(obj.log.entries)) return 'har';
    if (obj && typeof obj === 'object' && (obj.info || obj.openapi || obj.swagger)) return 'unsupported';
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

  if (format === 'unsupported') {
    return {
      format,
      requests: [],
      warnings: [
        '识别为暂不支持的集合格式（Postman Collection / OpenAPI / 其它 XML）。' +
          '当前支持：Burp XML 导出、HAR；或直接给单个 Burp/curl 文本请求。',
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
