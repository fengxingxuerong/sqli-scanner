// =====================================================================
// matchMetrics.js — 响应匹配多指标判定（对标 --string/--not-string/--text-only/
// --code/--regexp/--titles）+ WAF 拦截页防误报 + 反射剥离 + 多指标汇总。
// 自 Detector.js 拆出（纯搬移）：由 Detector.prototype 挂载（this 语义不变）。
// =====================================================================
import { isUnusableResponse, unusableReason as unusableReasonText } from '../egressOpts.js';
import { detectGenericBlock } from '../../core/waf/blockSignatures.js';

  /**
   * 锚点判定（对标 sqlmap --string / --not-string）：有锚点时优先用锚点判定页面语义，
   * 不依赖动态内容敏感的相似度比对。config.matchString=真页面必含文本；config.notString=假页面必含文本。
   * @param {string} body 响应体
   * @param {object} config 检测配置（含 matchString / notString）
   * @returns {boolean|null} 有锚点时返回 true（真页面）/ false（假页面）；无锚点返回 null（调用方回落分块比对）
   */
export function matchAnchors(body, config) {
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
export function _textOnly(body) {
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
export function matchText(trueBody, falseBody, config) {
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
export function _matchByCode(trueRes, falseRes, config) {
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
export function _toRegExp(pattern) {
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
export function _matchByRegexp(trueBody, falseBody, config) {
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
    if (!fre) return false;
    fre.lastIndex = 0;
    return fre.test(f) ? true : false;
  }

  // 提取 <title>...</title> 文本（无标题返回空串）
export function _extractTitle(body) {
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
export function _matchByTitle(trueBody, falseBody, config) {
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
export function _matchAnchorsPair(trueBody, falseBody, config) {
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
export function hasExplicitMatch(config) {
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
  /**
   * [P0-FIX 2026-09-09] 返回「本次响应不可用作判定输入」的原因（可用时空串）。
   * 为什么重要：网络失败与「目标返回空页」在旧代码里同形，两者都会被当成
   * 「真/假两侧无差异 → 不可注入」—— 那是把「没测成」写成「没洞」。
   * @param {object|null|undefined} res
   * @returns {string}
   */
export function unusableOf(res) {
    return isUnusableResponse(res) ? unusableReasonText(res) || '响应不可用' : '';
  }

  /**
   * [P0-FIX 2026-09-11] WAF 拦截页判定：真假对中任一侧是拦截页时，差异不可作注入证据。
   * 背景（waf-real echo 安全对照误报，2/2 复现）：CRS 对真/假 payload 的拦截是确定性的——
   * 真 payload 放行（200 ≈ 基线）、假 payload 被拦（403 拦截页 ≠ 基线），完美满足布尔判定
   * 三条件（真≈基线 / 假≠基线 / 真假有差异），且「组间稳定差异」复核还会强化它（拦截每次
   * 都一样）。这会把安全页误报为布尔注入。判定复用 detectGenericBlock（状态码门槛 +
   * 文案特征，裸 403 业务错误页不会被误判为 WAF）。
   * @param {object|null|undefined} res
   * @returns {boolean}
   */
export function _isWafBlockPage(res) {
    if (!res || typeof res !== 'object') return false;
    try {
      const r = detectGenericBlock(res);
      return !!(r && r.vendor === 'generic_block');
    } catch {
      return false;
    }
  }

  /**
   * [P0-FIX 2026-09-11] 布尔真假对防 WAF 误报总闸：任一侧是拦截页 → 该对不算命中。
   * 返回 true 表示「被拦截页污染，本对应跳过」。
   * @param {object|null|undefined} rTrue
   * @param {object|null|undefined} rFalse
   * @returns {boolean}
   */
export function _pairPollutedByWafBlock(rTrue, rFalse) {
    return this._isWafBlockPage(rTrue) || this._isWafBlockPage(rFalse);
  }

  /**
   * [P0-FIX 2026-09-11] 反射剥离：从响应体中剥掉被页面回显的注入 payload 自身。
   * 背景（multi-engine /num 布尔漏检）：回显型页面（`key = <payload>` / `id = <payload>`）
   * 把真/假 payload 原样渲染进响应，真/假页都被推离基线 → `真≈基线` 前提永不成立 →
   * 布尔通道在回显页上系统性漏检（无 WAF 也是 0 检出）。
   * 剥离语义（增量剥离）：payload 通常以 originalValue 开头（`1 AND 1=1-- ` 的 `1` 即原值，
   * 基线页回显的正是它）——整段剥离会把基线回显槽位一并剥掉，真页仍≠基线。
   * 故优先剥「payload 相对原值的增量」（保留 `id=1` 槽位）：真页剥离后≈基线 + 数据行，
   * 假页剥离后≈基线 + 空行，真假差异聚焦到 SQL 执行结果（1 行 vs 0 行）——这才是布尔
   * 判定应看的信号。payload 不以原值开头时回退整段剥离。
   * 对不回显的页面是零操作（零回归）。
   * @param {string} body 响应体
   * @param {string} payload 本次注入的 payload
   * @param {string} [orig] 注入点原始值（增量剥离的锚点）
   * @returns {string}
   */
export function _stripReflected(body, payload, orig) {
    let out = String(body ?? '');
    let p = String(payload ?? '');
    if (!p || p.length < 2) return out;
    // 增量剥离：payload 以原值开头 → 只剥增量（保留基线回显槽位）
    const o = String(orig ?? '');
    if (o && p.startsWith(o) && p.length > o.length) p = p.slice(o.length);
    const forms = new Set([p]);
    try {
      const decoded = decodeURIComponent(p.replace(/\+/g, ' '));
      if (decoded !== p) forms.add(decoded);
    } catch { /* 非法序列忽略 */ }
    // HTML 实体转义形态（常见三种引号 + 少量端点做全量转义）
    for (const base of [...forms]) {
      forms.add(base.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;'));
    }
    for (const f of forms) {
      // 替换为空串而非空格：回显槽位里 payload 增量剥掉后应精确回归基线形态
      // （`id=1 AND 1=1` 剥增量 → `id=1` ≈ 基线；若换成空格则 `id=1 ` ≠ 基线，实测像/不像判定被一个尾随空格毁掉）
      if (f.length >= 2 && out.includes(f)) out = out.split(f).join('');
    }
    return out;
  }

export function matchMetrics(trueRes, falseRes, config) {
    const tBody = String(trueRes?.data ?? '');
    const fBody = String(falseRes?.data ?? '');
    // [P0-FIX 2026-09-09] 任一侧不可用 → 返回 null（未定），而不是 false（无信号）：
    // false 会被调用方计入「已测且无差异」，null 让调用方跳过这一对并在必要时把点标成未决。
    if (this.unusableOf(trueRes) || this.unusableOf(falseRes)) return null;
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
export function _metricLabels(config) {
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
