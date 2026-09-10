// ============================================================================
// paramEncoding.js —— 参数值编码形态识别（base64 / 0x-hex）
//
// 背景（2026-09-11 独立红队评测 D14 靶点）：SPA / 移动端 API 常把参数值做 base64
// 编码后传输（`/api/order?id=MQ==`）。此类参数上直接投 SQL payload 是无效的——
// 服务端解码后才拼 SQL，payload 必须**先按同样规则编码**再发。
// 旧实现只能靠报错通道偶然命中，属碰运气；这里把「解码 → 注入 → 重新编码」补齐。
//
// 判定刻意保守（宁可漏识别，不可误识别）：误标会让该点的所有注入请求带上错误编码，
// 直接把一个正常注入点搞成"打不动"。
// ============================================================================

/**
 * 识别参数值的编码形态。
 * @param {*} value 参数原始值
 * @returns {{encoding:'base64'|'hex', decoded:string}|null}
 */
export function detectParamEncoding(value) {
  const s = String(value ?? '');
  if (s.length < 4) return null;

  // —— base64 ——（标准字母表 + 末尾补齐）
  if (s.length % 4 === 0 && /^[A-Za-z0-9+/]+={0,2}$/.test(s)) {
    const dec = safeDecodeBase64(s);
    if (dec && isPlausiblePlaintext(dec, s)) return { encoding: 'base64', decoded: dec };
  }

  // —— 0x 前缀 hex ——（不做裸 hex：长数字串会被误判成十六进制）
  if (/^0x[0-9a-fA-F]+$/.test(s) && s.length % 2 === 0) {
    const body = s.slice(2);
    let dec = '';
    try {
      for (let i = 0; i < body.length; i += 2) dec += String.fromCharCode(parseInt(body.slice(i, i + 2), 16));
    } catch { return null; }
    if (isPlausiblePlaintext(dec, s)) return { encoding: 'hex', decoded: dec };
  }

  return null;
}

function safeDecodeBase64(s) {
  try {
    const buf = Buffer.from(s, 'base64');
    // Buffer.from 对非法输入是宽容的：回编码必须一致，否则说明不是规范 base64
    if (buf.toString('base64').replace(/=+$/, '') !== s.replace(/=+$/, '')) return null;
    return buf.toString('utf8');
  } catch {
    return null;
  }
}

// 判定"解码结果像真实业务值"：可打印 ASCII 且比原文更短（编码的价值就在压缩语义）。
// 例：`MQ==`→'1' ✓、`dXNlcg==`→'user' ✓、`test`（解码出非可打印字节）✗、`abcd`→非可打印 ✗
function isPlausiblePlaintext(dec, original) {
  if (!dec) return false;
  if (dec.length >= original.length) return false;
  // 只接受可打印 ASCII（含常见符号）：二进制/中文/乱码一律不认
  return /^[\x20-\x7e]+$/.test(dec);
}

/**
 * 按注入点的编码形态把 payload 编码成"线上形态"。
 * 非编码点原样返回（零行为变化）。
 * @param {string} payload 原始 payload
 * @param {string|undefined} encoding 注入点编码形态
 * @returns {string} 待发送的值
 */
export function encodeForPoint(payload, encoding) {
  if (encoding === 'base64') return Buffer.from(String(payload), 'utf8').toString('base64');
  if (encoding === 'hex') {
    const hex = Buffer.from(String(payload), 'utf8').toString('hex');
    return `0x${hex}`;
  }
  return payload;
}

export default detectParamEncoding;
