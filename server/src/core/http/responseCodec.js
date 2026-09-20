// ============================================================================
// responseCodec.js —— 响应体的解压 / 字符集探测 / 解码 / 元数据挂载
//
// 从 httpClient.js（1900+ 行）抽离，[阶段② 拆上帝对象 2026-09-13]。
// 职责边界：只负责「字节 → 文本」与响应元数据，不持有任何连接/限速/代理状态，
// 便于单独测试与跨通道（axios / undici H2）复用。
// ============================================================================
import zlib from 'node:zlib';

const CHARSET_HEADER_RE = /(?:^|;)\s*charset\s*=\s*"?([^";\s]+)"?/i;
// <meta charset="x"> 与 <meta http-equiv="Content-Type" content="text/html; charset=x"> 共用一条：
// [^>] 保证只在单个标签内匹配
const META_CHARSET_RE = /<meta[^>]{0,300}?charset\s*=\s*["']?\s*([a-zA-Z0-9._:+-]+)/i;
// 预扫描窗口：只在 body 前 2048 字节（ASCII 视角）里找 <meta>，字符集声明必在 head 前部
const CHARSET_SNIFF_BYTES = 2048;
const UTF8_LABELS = new Set(['utf-8', 'utf8']);

/**
 * [P0-FIX 2026-09-09] 按 content-encoding 解包响应体（undici/H2 通道用；axios 通道自带解压）。
 * 只处理 Node zlib 能同步完成的编码；未知编码抛错，由调用方标注为「本次比对不可信」而不是静默。
 * @param {Buffer} buf 原始字节
 * @param {string} encoding content-encoding 头值（可含多段，如 `gzip, br` 时按最外层取最后一个）
 * @returns {Buffer} 解压后的字节
 */
export function decompressResponseBody(buf, encoding) {
  const chain = String(encoding || '')
    .split(',')
    .map((x) => x.trim().toLowerCase())
    .filter(Boolean);
  let out = buf;
  for (const enc of chain) {
    if (enc === 'identity') continue;
    if (enc === 'gzip' || enc === 'x-gzip') {
      out = zlib.gunzipSync(out);
    } else if (enc === 'deflate') {
      // RFC 7230 允许服务端直接发 raw deflate：先按 zlib 容器试，失败再按 raw 试
      try {
        out = zlib.inflateSync(out);
      } catch {
        out = zlib.inflateRawSync(out);
      }
    } else if (enc === 'br') {
      if (typeof zlib.brotliDecompressSync !== 'function') throw new Error('当前 Node 不支持 brotli');
      out = zlib.brotliDecompressSync(out);
    } else {
      throw new Error(`不支持的编码 ${enc}`);
    }
  }
  return out;
}

/**
 * 大小写不敏感地取响应头（兼容 axios AxiosHeaders / undici Headers / 普通对象）。
 * @param {object} headers 响应头
 * @param {string} name 头名（小写）
 * @returns {string} 头值（缺失时空串）
 */
export function getResponseHeader(headers, name) {
  if (!headers) return '';
  try {
    if (typeof headers.get === 'function') {
      const v = headers.get(name);
      if (v != null && v !== '') return String(v);
    }
  } catch { /* AxiosHeaders#get 对未知头会抛/返回 undefined，忽略后走索引取值 */ }
  const v = headers[name] ?? headers[name.toLowerCase()] ?? headers[name.toUpperCase()];
  if (v == null) return '';
  return String(Array.isArray(v) ? v[0] : v);
}

/**
 * 原始响应体 → Buffer（axios arraybuffer 给 Buffer；也兼容 ArrayBuffer / TypedArray）。
 * @param {*} data 响应体
 * @returns {Buffer|null} 非二进制输入返回 null
 */
export function toBuffer(data) {
  if (Buffer.isBuffer(data)) return data;
  if (data instanceof ArrayBuffer) return Buffer.from(data);
  if (ArrayBuffer.isView(data)) return Buffer.from(data.buffer, data.byteOffset, data.byteLength);
  return null;
}

// axios 的 text 通道会 stripBOM；解码路径必须保持一致，否则带 BOM 的响应长度/内容会变
function stripBom(s) {
  return s.charCodeAt(0) === 0xfeff ? s.slice(1) : s;
}

function normalizeCharsetLabel(raw) {
  const s = String(raw || '')
    .trim()
    .replace(/^["']|["';,]+$/g, '')
    .toLowerCase();
  return /^[a-z0-9][a-z0-9._:+-]{1,29}$/.test(s) ? s : '';
}

/**
 * 探测响应字符集：Content-Type charset= → HTML <meta charset>（前 2048 字节 ASCII 预扫描）→ 无。
 * @param {string} contentType Content-Type 头
 * @param {Buffer|null} buf 原始字节
 * @returns {{label:string, source:'header'|'meta'}|null}
 */
export function detectResponseCharset(contentType, buf) {
  const m = CHARSET_HEADER_RE.exec(String(contentType || ''));
  if (m) {
    const label = normalizeCharsetLabel(m[1]);
    if (label) return { label, source: 'header' };
  }
  if (buf && buf.length > 0) {
    // latin1 逐字节映射 → 正则只可能命中 ASCII，非 ASCII 字节不会伪造出 meta 标签
    const head = buf.subarray(0, CHARSET_SNIFF_BYTES).toString('latin1');
    if (head.includes('<meta')) {
      const mm = META_CHARSET_RE.exec(head);
      if (mm) {
        const label = normalizeCharsetLabel(mm[1]);
        if (label) return { label, source: 'meta' };
      }
    }
  }
  return null;
}

/**
 * 解码响应体为文本（两通道共用）。
 * 关键不变量：未声明字符集 / 声明 utf-8 时，结果与改动前（axios utf8 + stripBOM、undici
 * Buffer.toString('utf-8')）逐字符一致 —— utf-8 走 Node 原生解码，不进 TextDecoder。
 * @param {*} data 原始响应体（Buffer/ArrayBuffer/Uint8Array/string/undefined）
 * @param {object} [headers] 响应头
 * @returns {{text:string, charset:string, charsetSource:string, declaredCharset?:string, charsetUnsupported?:boolean}}
 */
export function decodeResponseBody(data, headers) {
  // 已是文本（HEAD 请求、被 mock 的传输层、历史调用方）→ 原样透传，绝不二次解码
  if (typeof data === 'string') {
    return { text: data, charset: 'utf-8', charsetSource: 'passthrough' };
  }
  const buf = toBuffer(data);
  if (!buf || buf.length === 0) {
    return { text: '', charset: 'utf-8', charsetSource: data === undefined || data === null ? 'none' : 'empty' };
  }
  const found = detectResponseCharset(getResponseHeader(headers, 'content-type'), buf);
  if (!found || UTF8_LABELS.has(found.label)) {
    return {
      text: stripBom(buf.toString('utf8')),
      charset: 'utf-8',
      charsetSource: found ? found.source : 'fallback',
    };
  }
  try {
    return {
      text: new TextDecoder(found.label, { fatal: false }).decode(buf),
      charset: found.label,
      charsetSource: found.source,
    };
  } catch {
    // Node 无该解码器（ICU 缺表 / 私有别名如 x-big5）→ 回退 utf-8 并标记，
    // 让报告能区分「目标本来就是乱码」与「解码器缺失」
    return {
      text: stripBom(buf.toString('utf8')),
      charset: 'utf-8',
      charsetSource: 'fallback',
      declaredCharset: found.label,
      charsetUnsupported: true,
    };
  }
}

/**
 * 读取响应对象上的 __meta（非枚举元数据）。
 * @param {object} res 响应对象
 * @returns {object} 元数据副本（缺省空对象）
 */
export function getResMeta(res) {
  if (!res || typeof res !== 'object' || !res.__meta) return {};
  return { ...res.__meta };
}

/**
 * 合并写入响应元数据（④：截断 / 字符集 / insecureTls / viaProxy）。
 * 与 __networkMs 同样用非枚举属性：不污染 JSON 序列化与任何 {...res} 透传路径。
 * @param {object} res 响应对象
 * @param {object} meta 待合并字段
 * @returns {object} res
 */
export function attachResMeta(res, meta) {
  if (!res || typeof res !== 'object') return res;
  const merged = { ...(res.__meta && typeof res.__meta === 'object' ? res.__meta : {}), ...(meta || {}) };
  try {
    Object.defineProperty(res, '__meta', {
      value: merged,
      enumerable: false,
      configurable: true,
      writable: true,
    });
  } catch {
    try {
      res.__meta = merged; // 冻结/异常对象兜底（不致命）
    } catch { /* ignore */ }
  }
  return res;
}

/**
 * [大文件二期拆分 2026-09-20] axios 通道响应后处理：解码文本（对外仍是 string）+ 挂 __meta。
 *
 * 从 httpClient.js 的 `HttpClient#_finishResponse` 原样外移（行为零变化），归位理由是它
 * 与 undici 通道的收尾逻辑共用同一元数据契约，本就属于「字节 → 文本 + 元数据」这一职责。
 *
 * 不变量：
 *   · 无响应体（HEAD/204/被 mock 的传输层）→ 直接返回原对象，**不造数据**；
 *   · 超限在 axios 侧是「抛错」而非截断（maxContentLength 命中即 reject），故 truncated 恒 false；
 *     真正的静默截断风险在 undici 通道（见 httpClient#_rawUndici）。
 * @param {any} res axios 原始响应（res.data 为 arraybuffer）
 * @param {any} [opts] 请求选项（本函数当前不消费，保留签名以便与 undici 通道对齐）
 * @returns {any} 就地改写 res.data 为 string 后的同一对象
 */
export function finalizeAxiosResponse(res, opts) {
  if (!res || typeof res !== 'object') return res;
  const raw = res.data;
  if (raw === undefined || raw === null) return res; // 无响应体：不造数据
  const buf = toBuffer(raw);
  const bodyBytes = buf ? buf.length : Buffer.byteLength(String(raw), 'utf8');
  const decoded = decodeResponseBody(raw, res.headers);
  res.data = decoded.text;
  attachResMeta(res, {
    bodyBytes,
    truncated: false,
    charset: decoded.charset,
    charsetSource: decoded.charsetSource,
    ...(decoded.charsetUnsupported
      ? { charsetUnsupported: true, declaredCharset: decoded.declaredCharset }
      : {}),
  });
  return res;
}

