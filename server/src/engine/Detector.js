import { obfuscateWithConfig } from '../core/tamper/applyTampers.js';
import { chunkSimilarity, chunkHashes, dynamicBlockFilter } from '../core/statsHelper.js';
import { buildInjectionRequest } from './injection.js';

/**
 * [P0 导出] 排除动态块的相似判定构建器（独立函数）。
 * 供 Detector.buildDynamicSimilar 与 Extractor 提取阶段（_dynJudge）共用，
 * 保证检测与提取两层的动态内容感知逻辑不漂移。
 * @param {string[]} baselines 同一注入点的多次基线响应体
 * @returns {function|null} (a, b) => boolean 相似判定；无动态块时返回 null
 */
export function buildDynamicSimilarFn(baselines) {
  const { dynamicIdx } = dynamicBlockFilter(baselines);
  if (!dynamicIdx || dynamicIdx.size === 0) return null;
  return (a, b) => {
    const sa = String(a ?? '');
    const sb = String(b ?? '');
    if (sa === sb) return true;
    if (Math.abs(sa.length - sb.length) > Math.max(24, Math.max(sa.length, sb.length) * 0.12)) return false;
    const ha = chunkHashes(sa);
    const hb = chunkHashes(sb);
    const n = Math.max(ha.length, hb.length, 1);
    let same = 0;
    let total = 0;
    for (let k = 0; k < n; k++) {
      if (dynamicIdx.has(k)) continue; // 跳过动态块
      total++;
      if ((ha[k] ?? 0) === (hb[k] ?? 0)) same++;
    }
    return total === 0 ? true : same / total >= 0.85;
  };
}

// 检测器接口/基类（策略模式）
// 子类需实现 detect(ctx)，返回 DetectionResult。
// ctx 约定：{ httpClient, target, point, dbms, config }
export class Detector {
  /**
   * @param {string} technique 检测技术名（union/error/boolean/time）
   */
  constructor(technique) {
    this.technique = technique;
  }

  // 由子类实现具体检测逻辑
  async detect(ctx) {
    throw new Error('Detector.detect 必须由子类实现');
  }

  /**
   * 按注入点位置构造请求对象（注入位置：url/body/cookie/header）
   * @param {object} target 目标
   * @param {object} point 注入点
   * @param {string} injectedValue 注入后的参数值
   */
  buildRequest(target, point, injectedValue) {
    // P1-A3：请求构造三份复制收敛为单一 buildInjectionRequest（injection.js 已完整覆盖
    // direct/url/body/cookie/header + 表单点回退，Detector 不再自建副本）。
    return buildInjectionRequest(target, point, injectedValue);
  }

  /**
   * 按 WAF 规避配置包裹混淆（tamper 链式优先，否则 legacy obfuscate，否则原样）。
   * 统一改调 obfuscateWithConfig，向后兼容：tamper 关且 obfuscate 关时返回原样。
   * @param {object} ctx 检测上下文（含 config.wafEvasion）
   * @param {string} value 已填充的注入值
   * @returns {string} 混淆后（或原样）的注入值
   */
  obfuscateValue(ctx, value) {
    return obfuscateWithConfig(value, ctx);
  }

  /**
   * 闭合上下文探测（对标 sqlmap boundary 系统）：识别注入点是否需要引号/括号闭合前缀。
   * 思路：对每个候选闭合前缀追加「恒真条件 AND 1=1」，若响应 ≈ 基线，说明该前缀使查询语法
   * 恢复正常且结果集不变（正确闭合 → 与基线一致；错误闭合 → 语法错误/空集 → 明显偏离）。
   * 返回命中的闭合前缀（无包裹返回空串）。探测失败回退空串（不阻塞检测）。
   * @param {object} ctx { httpClient, target, point, config }
   * @returns {Promise<string>} 闭合前缀，如 '' / "'" / "')" / "'))" / '"' / '")'
   */
  async probeBoundary(ctx) {
    const { httpClient, target, point, config } = ctx;
    const orig = point.originalValue || '1';
    // 候选闭合前缀按出现频率排序：无包裹 / 单引号 / 单引号+括号 / 双引号 / 双引号+括号 / 反引号 / 双引号双括号
    // payload 子代理建议补全：反引号（MySQL 标识符包裹）与 "))（双引号双括号场景）
    const candidates = ['', "'", "')", "'))", '"', '")', '`', '"))'];
    try {
      const baseRes = await this.send(httpClient, ctx, this.buildRequest(target, point, orig), ctx);
      const baseBody = String(baseRes?.data ?? '');
      const baseStatus = baseRes?.status ?? null;
      // 首请求自动学习页面特征：提取 <title> 供后续 matchTitle 使用
      point._baselineTitle = this._extractTitle(baseBody);
      // 并行探测 8 个闭合候选（原串行，独立请求可并发）
      const results = await Promise.allSettled(
        candidates.map((prefix) => {
          const payload = `${orig}${prefix} AND 1=1-- -`;
          return this.send(httpClient, ctx, this.buildRequest(target, point, payload), ctx)
            .then((r) => ({ prefix, body: String(r?.data ?? ''), status: r?.status }));
        })
      );
      const hit = results.find((r) => r.status === 'fulfilled' && this._boundarySimilar(baseBody, baseStatus, r.value.body, r.value.status, config));
      if (hit) return hit.value.prefix;
    } catch {
      /* 探测失败回退空前缀 */
    }
    return '';
  }

  /**
   * 锚点判定（对标 sqlmap --string / --not-string）：有锚点时优先用锚点判定页面语义，
   * 不依赖动态内容敏感的相似度比对。config.matchString=真页面必含文本；config.notString=假页面必含文本。
   * @param {string} body 响应体
   * @param {object} config 检测配置（含 matchString / notString）
   * @returns {boolean|null} 有锚点时返回 true（真页面）/ false（假页面）；无锚点返回 null（调用方回落分块比对）
   */
  matchAnchors(body, config) {
    const cfg = config || {};
    const text = String(body ?? '');
    const ms = cfg.matchString;
    if (ms != null && String(ms) !== '') return text.includes(String(ms));
    const ns = cfg.notString;
    if (ns != null && String(ns) !== '') return !text.includes(String(ns));
    return null;
  }

  // —— 响应匹配多指标判定（对标 sqlmap --text-only / --code / --regexp / --titles）——
  // 语义统一为：对「真/假」两个响应，指标命中（真≠假）即返回 true（注入信号），
  // 无差异返回 false，未配置返回 null（调用方回落 blindRobust 统计 + 分块比对，默认路径不变）。

  /**
   * 剥离 HTML 标签，仅保留纯文本（对标 sqlmap --text-only）。
   * 粗粒度去标签：先剔除 script/style/注释内容，再去除标签本身并折叠空白。
   * 用于 HTML 里动态内容（时间戳/CSRF）多、但纯文本稳定的场景。
   * @param {string} body 响应体
   * @returns {string} 纯文本
   */
  _textOnly(body) {
    let s = String(body ?? '');
    s = s.replace(/<script[\s\S]*?<\/script>/gi, ' ');
    s = s.replace(/<style[\s\S]*?<\/style>/gi, ' ');
    s = s.replace(/<!--[\s\S]*?-->/g, ' ');
    s = s.replace(/<[^>]*>/g, ' ');
    s = s
      .replace(/&nbsp;/gi, ' ')
      .replace(/&amp;/gi, '&')
      .replace(/&lt;/gi, '<')
      .replace(/&gt;/gi, '>')
      .replace(/&quot;/gi, '"')
      .replace(/&#39;|&apos;/gi, "'");
    return s.replace(/\s+/g, ' ').trim();
  }

  /**
   * 纯文本比对（对标 --text-only）：剥标签后真/假纯文本不一致即信号。
   * @param {string} trueBody 真响应体
   * @param {string} falseBody 假响应体
   * @param {object} config 检测配置（config.matchText === true 才启用）
   * @returns {boolean|null} true=信号（真≠假）、false=无差异、null=未启用
   */
  matchText(trueBody, falseBody, config) {
    if (!config || config.matchText !== true) return null;
    const t = this._textOnly(trueBody);
    const f = this._textOnly(falseBody);
    return t === f ? false : true;
  }

  /**
   * 状态码判定（对标 --code）：真/假响应状态码不同即信号。
   * config.matchCode 可指定期望真/假状态码 { true:200, false:500 }（精确匹配即信号）；
   * 未指定（matchCode===true 或空对象）用「真假状态码不同」作为弱信号。
   * @param {object} trueRes 真响应对象（含 status）
   * @param {object} falseRes 假响应对象（含 status）
   * @param {object} config 检测配置（config.matchCode 非空才启用）
   * @returns {boolean|null} true=信号、false=无差异、null=未启用
   */
  _matchByCode(trueRes, falseRes, config) {
    const mc = config && config.matchCode;
    if (!mc) return null;
    const t = trueRes && trueRes.status;
    const f = falseRes && falseRes.status;
    // 显式指定真/假期望状态码：按期望精确匹配
    if (typeof mc === 'object' && (mc.true != null || mc.false != null)) {
      const tOk = mc.true == null || t === mc.true;
      const fOk = mc.false == null || f === mc.false;
      return tOk && fOk ? true : false;
    }
    // 弱信号：仅要求真/假状态码不同
    if (t == null || f == null) return false;
    return t !== f;
  }

  // 把 string/RegExp 统一成 RegExp；非法正则返回 null（不抛，调用方回落）
  _toRegExp(pattern) {
    if (pattern instanceof RegExp) return pattern;
    try {
      return new RegExp(String(pattern));
    } catch {
      return null;
    }
  }

  /**
   * 正则判定（对标 --regexp）：真响应命中、假响应不命中（或反之）即信号。
   * config.matchRegexp 单个正则（真命中、假不命中即信号，反向亦然）；
   * config.trueRegexp / falseRegexp 分别限定真/假侧需命中的正则。
   * @param {string} trueBody 真响应体
   * @param {string} falseBody 假响应体
   * @param {object} config 检测配置
   * @returns {boolean|null} true=信号、false=无差异、null=未启用
   */
  _matchByRegexp(trueBody, falseBody, config) {
    const cfg = config || {};
    const t = String(trueBody ?? '');
    const f = String(falseBody ?? '');
    const single = cfg.matchRegexp;
    if (single != null && String(single) !== '') {
      const re = this._toRegExp(single);
      if (!re) return null;
      re.lastIndex = 0; // P2-21: 重置 lastIndex，防止 g/y 标志导致状态泄漏
      const tHit = re.test(t);
      re.lastIndex = 0;
      const fHit = re.test(f);
      return tHit !== fHit ? true : false;
    }
    const tre = cfg.trueRegexp != null && String(cfg.trueRegexp) !== '' ? this._toRegExp(cfg.trueRegexp) : null;
    const fre = cfg.falseRegexp != null && String(cfg.falseRegexp) !== '' ? this._toRegExp(cfg.falseRegexp) : null;
    if (!tre && !fre) return null;
    if (tre && fre) {
      tre.lastIndex = 0; fre.lastIndex = 0;
      return tre.test(t) && fre.test(f) ? true : false;
    }
    if (tre) { tre.lastIndex = 0; return tre.test(t) ? true : false; }
    fre.lastIndex = 0;
    return fre.test(f) ? true : false;
  }

  // 提取 <title>...</title> 文本（无标题返回空串）
  _extractTitle(body) {
    const s = String(body ?? '');
    const m = s.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
    return m ? m[1].replace(/\s+/g, ' ').trim() : '';
  }

  /**
   * 标题判定（对标 --titles）：真/假 <title> 不同即信号。
   * @param {string} trueBody 真响应体
   * @param {string} falseBody 假响应体
   * @param {object} config 检测配置（config.matchTitle === true 才启用）
   * @returns {boolean|null} true=信号（标题不同）、false=无差异、null=未启用
   */
  _matchByTitle(trueBody, falseBody, config) {
    if (!config || config.matchTitle !== true) return null;
    const t = this._extractTitle(trueBody);
    const f = this._extractTitle(falseBody);
    return t === f ? false : true;
  }

  /**
   * 锚点真/假对判定（复用 matchAnchors 语义，扩展到真假对）：
   * matchString 配置 → 真页含、假页不含即信号；notString 配置 → 真页不含、假页含即信号。
   * @param {string} trueBody 真响应体
   * @param {string} falseBody 假响应体
   * @param {object} config 检测配置
   * @returns {boolean|null} true=信号、false=无差异、null=未启用
   */
  _matchAnchorsPair(trueBody, falseBody, config) {
    const cfg = config || {};
    const t = String(trueBody ?? '');
    const f = String(falseBody ?? '');
    const ms = cfg.matchString;
    if (ms != null && String(ms) !== '') {
      return t.includes(String(ms)) && !f.includes(String(ms)) ? true : false;
    }
    const ns = cfg.notString;
    if (ns != null && String(ns) !== '') {
      return !t.includes(String(ns)) && f.includes(String(ns)) ? true : false;
    }
    return null;
  }

  /**
   * 是否显式配置了响应匹配指标（--string/--not-string/--text-only/--code/--regexp/--titles）。
   * 有任一显式指标即返回 true，检测器据此切换判定路径（未配置回退默认盲注判定）。
   * @param {object} config 检测配置
   * @returns {boolean}
   */
  hasExplicitMatch(config) {
    const cfg = config || {};
    if (cfg.matchString != null && String(cfg.matchString) !== '') return true;
    if (cfg.notString != null && String(cfg.notString) !== '') return true;
    if (cfg.matchText === true) return true;
    if (cfg.matchTitle === true) return true;
    if (cfg.matchCode) return true;
    if (cfg.matchRegexp != null && String(cfg.matchRegexp) !== '') return true;
    if (cfg.trueRegexp != null && String(cfg.trueRegexp) !== '') return true;
    if (cfg.falseRegexp != null && String(cfg.falseRegexp) !== '') return true;
    return false;
  }

  /**
   * 响应匹配多指标汇总判定：任一显式指标判「真≠假」即返回 true（注入信号）；
   * 显式指标全部判「无差异」返回 false；未配置任何指标返回 null（回落默认路径）。
   * @param {object} trueRes 真响应对象
   * @param {object} falseRes 假响应对象
   * @param {object} config 检测配置
   * @returns {boolean|null}
   */
  matchMetrics(trueRes, falseRes, config) {
    const tBody = String(trueRes?.data ?? '');
    const fBody = String(falseRes?.data ?? '');
    const checks = [
      () => this._matchAnchorsPair(tBody, fBody, config),
      () => this._matchByCode(trueRes, falseRes, config),
      () => this.matchText(tBody, fBody, config),
      () => this._matchByRegexp(tBody, fBody, config),
      () => this._matchByTitle(tBody, fBody, config),
    ];
    let anyConfigured = false;
    for (const fn of checks) {
      const r = fn();
      if (r === null) continue;
      anyConfigured = true;
      if (r === true) return true;
    }
    return anyConfigured ? false : null;
  }

  // 已配置响应匹配指标的标签列表（供 evidence 展示用）
  _metricLabels(config) {
    const cfg = config || {};
    const out = [];
    if (cfg.matchString != null && String(cfg.matchString) !== '') out.push('string');
    if (cfg.notString != null && String(cfg.notString) !== '') out.push('not-string');
    if (cfg.matchText === true) out.push('text-only');
    if (cfg.matchCode) out.push('code');
    if (cfg.matchRegexp != null && String(cfg.matchRegexp) !== '') out.push('regexp');
    if (cfg.trueRegexp != null && String(cfg.trueRegexp) !== '') out.push('true-regexp');
    if (cfg.falseRegexp != null && String(cfg.falseRegexp) !== '') out.push('false-regexp');
    if (cfg.matchTitle === true) out.push('titles');
    return out.join('/');
  }

  /**
   * 分块比对相似度（对标 sqlmap 页面比较引擎）：先走长度容差 + 最长公共前缀（快速路径），
   * LCP 未达标时用分块相似率兜底——首部动态内容（时间戳/anti-CSRF token）不再让整串 LCP 崩塌。
   * P2-P8 CPU 比对下沉：大 body（>64KB）用首尾采样近似判定，避免逐字符 LCP 扫描（与
   * BooleanBlindDetector._similar 对齐）——首尾采样能确认相似时直接返回（省整串分块 hash）；
   * 首/尾不匹配（可能含动态首块）时回落分块相似率兜底，语义不弱化。
   * @param {string} a 基准响应体
   * @param {string} b 待比对响应体
   * @returns {boolean} 是否判相似
   */
  chunkedSimilar(a, b) {
    if (a === b) return true;
    const la = a.length;
    const lb = b.length;
    if (Math.abs(la - lb) > Math.max(24, Math.max(la, lb) * 0.12)) return false;
    if (la === 0 || lb === 0) return la === lb;
    if (la > 65536 || lb > 65536) {
      // 大 body 快速路径：首尾各取 256 字符采样；均匹配（同长度时含尾段）→ 判相似（省整串 hash）；
      // 任一不匹配 → 不能轻率判相似，回落分块相似率兜底（动态首块场景不变）。
      const m = Math.min(la, lb);
      const head = 256;
      const tail = 256;
      const headOk = a.slice(0, head) === b.slice(0, head);
      const tailOk = la !== lb || a.slice(m - tail) === b.slice(m - tail);
      if (headOk && tailOk) return true;
      return chunkSimilarity(a, b) >= 0.85;
    }
    const m = Math.min(la, lb);
    let common = 0;
    while (common < m && a[common] === b[common]) common++;
    if (common >= m * 0.85) return true;
    return chunkSimilarity(a, b) >= 0.85;
  }

  /**
   * 自动动态块识别（深化 chunkedSimilar）：对基线两两比对，标记「高频差异块下标」为动态块，
   * 返回排除动态块后的相似判定函数（长度容差 + 非动态块相似率 ≥ 0.85）。
   * config.autoDynamicBlock === true 才启用；关闭或无动态块时返回 null（回落现状分块比对，默认路径不变）。
   * @param {string[]} baselines 同一注入点的多次基线响应体
   * @param {object} config 检测配置（含 autoDynamicBlock 开关）
   * @returns {function|null} 排除动态块后的相似判定 (a, b) => boolean；关闭/无动态块返回 null
   */
  buildDynamicSimilar(baselines, config) {
    if (!config || config.autoDynamicBlock !== true) return null;
    return buildDynamicSimilarFn(baselines);
  }

  // 闭合探测的相似判定：锚点优先 → 状态码一致 + 分块比对（长度容差 + LCP + 分块相似率兜底）。
  // （P1-D4：从单纯 LCP 升级为分块比对 + 锚点，首部动态内容场景不再误判）
  _boundarySimilar(baseBody, baseStatus, body, status, config) {
    const anchored = this.matchAnchors(body, config);
    if (anchored !== null) {
      if (anchored === false) return false;
      // ★FIX [P0]：anchored===true 时验证基线也命中 matchString。
      // 若基线和注入后都命中，说明 matchString 过于常见（如 '<html'）→
      // 锚点恒命中 → 闭合探测总返回空前缀 → 漏报。回落分块比对精确判断。
      const baseAnchored = this.matchAnchors(baseBody, config);
      if (baseAnchored !== true) return true;
    }
    if (baseStatus != null && status != null && status !== baseStatus) return false;
    return this.chunkedSimilar(baseBody, body);
  }

  // 经统一 HttpClient 发送请求，并透传 proxy/auth/wafEvasion
  async send(httpClient, ctx, req, opts = {}) {
    const config = (ctx && ctx.config) || {};
    return httpClient.request({
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
      // 网络耗时测量（时间盲注判定用）：HttpClient 在令牌获取完成后计 __networkMs
      networkTiming: opts.networkTiming,
      // [sqlmap 对标] --delay / --reqrate / --max-requests：透传限速与请求上限配置
      delay: config.delay ?? 0,
      reqRate: config.reqRate ?? 0,
      maxReq: config.maxReq ?? 0,
      // [P1-FIX 2026-09-05] Cookie Jar 开关透传：config.cookieJar 默认开（自动会话保持）；
      // config.dropSetCookie=true 对标 sqlmap --drop-set-cookie（不吸收服务端会话）
      cookieJar: config.cookieJar !== false,
      dropSetCookie: config.dropSetCookie === true,
    });
  }

  /**
   * [sqlmap 对标] --null-connection：发送 HEAD 请求（无响应体传输），用于布尔盲注快速判定。
   * config.nullConnection === true 时，boolean/time 检测器应调用此方法替代 send。
   * @param {object} httpClient 统一 HttpClient（需支持 headRequest 方法）
   * @param {object} ctx 检测上下文（含 config）
   * @param {object} req 请求对象（含 url / params / headers 等）
   * @param {object} [opts] 额外选项
   * @returns {Promise<{status:number, headers:object, data:string}>}
   */
  async sendHead(httpClient, ctx, req, opts = {}) {
    const config = (ctx && ctx.config) || {};
    if (typeof httpClient.headRequest !== 'function') {
      // 兜底：httpClient 不支持 headRequest 时回退到 send（保持兼容性）
      return this.send(httpClient, ctx, req, opts);
    }
    return httpClient.headRequest(req.url, {
      headers: req.headers,
      timeoutMs: opts.timeoutMs ?? config.timeoutMs,
      retry: opts.retry ?? config.retry,
      proxy: config.proxy ?? false,
      auth: config.auth ?? null,
      wafEvasion: config.wafEvasion ?? null,
      delay: config.delay ?? 0,
      reqRate: config.reqRate ?? 0,
      maxReq: config.maxReq ?? 0,
    });
  }

  /**
   * [sqlmap 对标] --null-connection：基于状态码 + Content-Length 头的真假判定。
   * 不依赖响应体相似度比对，仅比较 HTTP 元数据。
   * 判定逻辑：
   *   - 状态码不同 → 信号（true，真假可区分）
   *   - 状态码相同但 Content-Length 不同 → 信号
   *   - 两者均相同 → 无差异（false）
   * @param {{status:number, headers:object}} response 待判定响应
   * @param {{status:number, headers:object}} baselineResponse 基线响应
   * @returns {boolean} true=可区分（注入信号），false=无差异
   */
  matchNullConnection(response, baselineResponse) {
    const r = response || {};
    const b = baselineResponse || {};
    // 状态码不同即信号
    const rStatus = r.status ?? 0;
    const bStatus = b.status ?? 0;
    if (rStatus !== bStatus) return true;
    // Content-Length 头比对
    const rLen = this._contentLength(r.headers);
    const bLen = this._contentLength(b.headers);
    if (rLen != null && bLen != null && rLen !== bLen) return true;
    return false;
  }

  // 从响应头取 Content-Length 数值（大小写不敏感），无则返回 null
  _contentLength(headers) {
    if (!headers || typeof headers !== 'object') return null;
    for (const [k, v] of Object.entries(headers)) {
      if (k.toLowerCase() === 'content-length') {
        const n = Number(v);
        return Number.isFinite(n) ? n : null;
      }
    }
    return null;
  }

  /**
   * 限并发发送一批请求：保持入参顺序返回结果数组，单个失败不中断整体。
   * 用于盲注基线与真假对重复采样，抵消串行 await 带来的 ~2.8× 开销。
   * 每个返回元素结构：{ resp, __elapsed(ms), __totalMs(ms), __error? }；发送失败仅置 __error，不抛。
   * —— 计时语义（本版）——
   * __elapsed 优先取 HttpClient 的纯网络耗时（__networkMs，不含令牌桶排队等待）：
   * 旧实现从 send 前计时，限速低时并发采样的排队时间被计入，基线 μ/σ 与注入耗时虚高
   * （见 docs/vs-sqlmap-analysis/01-detection.md 的已知风险）。mock 客户端无 __networkMs 时
   * 回退总耗时（与旧行为一致，零回归）；__totalMs 始终为总耗时（含排队）。
   * @param {object} httpClient
   * @param {object} ctx
   * @param {object[]} requests buildRequest 结果数组
   * @param {object} opts 透传给 send 的 opts（如 timeoutMs / networkTiming）
   * @param {number} limit 并发上限（默认 4，盲注用 rb.concurrency）
   */
  async sendConcurrent(httpClient, ctx, requests, opts = {}, limit = 4) {
    const out = new Array(requests.length);
    let cursor = 0;
    const worker = async () => {
      while (cursor < requests.length) {
        const i = cursor++;
        const t0 = Date.now();
        try {
          const resp = await this.send(httpClient, ctx, requests[i], opts);
          const totalMs = Date.now() - t0;
          const networkMs = resp && typeof resp.__networkMs === 'number' ? resp.__networkMs : null;
          out[i] = { resp, __elapsed: networkMs ?? totalMs, __totalMs: totalMs };
        } catch (e) {
          out[i] = { __error: e, __elapsed: Date.now() - t0, __totalMs: Date.now() - t0 };
        }
      }
    };
    const n = Math.max(1, Math.min(limit || 1, requests.length));
    await Promise.all(Array.from({ length: n }, () => worker()));
    return out;
  }
}

export default Detector;
