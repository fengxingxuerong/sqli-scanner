import { Detector } from '../Detector.js';
import { createDetectionResult } from '../models.js';
import { PAYLOADS, SECOND_ORDER_PROBES, ERROR_SIG, fillPayload } from '../payloads.js';
import { ErrorCode, AppError } from '../../core/errors.js';

// 二阶注入检测器（Second-order / Stored SQLi）
// 策略模式与现有 Detector 子类一致：detect(ctx) 返回 createDetectionResult 形状。
//
// 核心差异：一阶检测是"单点单轮即时回显"，二阶是"先存储、后触发"的两阶段时序。
// 本检测器只对"已标记的存储点（isStorePoint）+ 编排层注入的触发页（ctx.triggerUrl）"工作，
// 不在 ScanManager.detectors 数组中参与一阶 per-point 循环（由 ScanManager 独立补充趟调用）。
//
// 判定三态：基线（存储前读触发页，不写）/ 实验（存报错探针后读触发页）/ 阴性对照（存良性值后读）。
// 仅当「基线无报错 && 实验有报错 && 阴性无报错」判定为二阶注入。命中即确认，不做拖库（与 oob 一致）。
export class SecondOrderDetector extends Detector {
  constructor() {
    super('second_order');
  }

  /**
   * @param {object} ctx {
   *   httpClient, target, point, dbms, config,
   *   triggerUrl: string  // ← 由 ScanManager._runSecondOrder 逐次注入
   * }
   * @returns {Promise<import('../models.js').DetectionResult>}
   */
  async detect(ctx) {
    const { httpClient, target, point, dbms, config, triggerUrl } = ctx;
    const result = createDetectionResult(point.id, 'second_order');

    // 无触发页 → 无法判定，直接未命中（不发起任何请求）
    if (!triggerUrl) return result;

    const so = (config && config.secondOrder) || {};
    if (!so.enabled) {
      // 防御性：编排层已门控，但直达 detect 时也应拒绝（避免误对目标发起写请求）
      throw new AppError(ErrorCode.SECOND_ORDER_DISABLED, '二阶检测未启用');
    }

    // 1) 基线：只读触发页，记录是否本就含报错特征（不写）
    const baselineBody = await this._trigger(httpClient, ctx, triggerUrl);
    const baselineErr = ERROR_SIG.test(baselineBody);

    // 2) [编排增强] 存储→检索链路验证：先存一个唯一哨兵值，读触发页，断言哨兵被回显。
    //    这证明"该存储点写入的值确实被触发页读出并拼入响应"——二阶注入成立的前提。
    //    若哨兵未回显，说明存储点与触发页之间没有检索链路（或触发页并非读取该字段），
    //    后续存储报错探针的"触发页报错"无法归因于二阶，直接判定未命中，避免误报。
    const sentinel = `__so_${Math.random().toString(36).slice(2, 10)}__`;
    await this._store(httpClient, ctx, sentinel);
    const sentinelBody = await this._trigger(httpClient, ctx, triggerUrl);
    if (!String(sentinelBody).includes(sentinel)) {
      result.evidence =
        `二阶链路验证失败：存储哨兵 ${sentinel} 未在触发页 ${triggerUrl} 回显，` +
        `存储点→触发页的检索链路不通，跳过该点（避免误报）`;
      return result; // vulnerable 仍为 false
    }

    // 3) 存储阶段（真实写）：构造报错探针 → 可选刷新 CSRF → POST 表单点
    const probe = this._buildProbe(ctx, dbms);
    if (so.refreshCsrf) {
      await this._refreshCsrf(httpClient, ctx); // GET actionUrl 重抓 token 覆盖 formValues（best-effort）
    }
    await this._store(httpClient, ctx, probe);

    // 3) 触发阶段：读触发页，看是否回显报错
    const expBody = await this._trigger(httpClient, ctx, triggerUrl);
    const expErr = ERROR_SIG.test(expBody);

    // 4) 阴性对照（可选）：存良性值 → 读触发页应无报错（提高判定置信）
    let negErr = false;
    if (so.negativeControl) {
      const benign = point.originalValue && String(point.originalValue).trim() ? point.originalValue : 'benign';
      await this._store(httpClient, ctx, benign);
      const negBody = await this._trigger(httpClient, ctx, triggerUrl);
      negErr = ERROR_SIG.test(negBody);
    }

    // 5) 判定：基线无 / 实验有 / 阴性无 → 二阶注入确认
    if (!baselineErr && expErr && !negErr) {
      result.vulnerable = true;
      result.dbms = dbms || null;
      result.evidence =
        `二阶注入确认：存储探针后在触发页 ${triggerUrl} 回显数据库报错（基线无、实验有、阴性无），` +
        `存储点 ${point.param}@${point.actionUrl} 的数据被读出后重新拼入查询触发注入`;
      result.payloads = [probe];
      point.confirmed = true;
      point.technique = 'second_order';
      point.dbms = dbms || point.dbms;
    }
    return result;
  }

  /**
   * 构造存储探针：已知 dbms 优先取该库 error 模板（填 {ORIG}=原始值），否则回退 SECOND_ORDER_PROBES。
   * 经 obfuscateValue 走 tamper 链（与 ErrorDetector 一致，WAF 规避可用）。
   * @param {object} ctx 检测上下文（含 point.originalValue）
   * @param {string} dbms 已知数据库类型（可空）
   * @returns {string} 已混淆的探针值
   */
  _buildProbe(ctx, dbms) {
    const orig = (ctx.point && ctx && ctx.point.originalValue) || '1';
    let template;
    if (dbms && PAYLOADS[dbms] && Array.isArray(PAYLOADS[dbms].error) && PAYLOADS[dbms].error.length) {
      // 复用一阶报错模板（已验证可触发回显报错），仅取首个
      template = PAYLOADS[dbms].error[0];
    } else {
      template = SECOND_ORDER_PROBES[0];
    }
    const filled = fillPayload(template, { orig });
    return this.obfuscateValue(ctx, filled);
  }

  /**
   * 存储阶段：构造表单 POST 请求（含 CSRF 等全部字段）并经统一 HttpClient 发送（真实写）。
   * @param {object} httpClient 统一 HttpClient
   * @param {object} ctx 检测上下文（含 target / point）
   * @param {string} value 要存储的值（探针/良性值）
   */
  async _store(httpClient, ctx, value) {
    // 复用基类 buildRequest：表单点已自动并入 formValues（含 CSRF），再把当前注入参数覆盖为 value
    const req = this.buildRequest(ctx.target, ctx.point, value);
    await this.send(httpClient, ctx, req);
  }

  /**
   * 触发阶段：GET 触发页，返回响应体字符串（经统一 HttpClient）。
   * @param {object} httpClient 统一 HttpClient
   * @param {object} ctx 检测上下文（含 target）
   * @param {string} url 触发页 URL
   * @returns {Promise<string>}
   */
  async _trigger(httpClient, ctx, url) {
    const req = {
      method: 'GET',
      url,
      params: {},
      data: {},
      headers: { ...(ctx.target.headerParams || {}) },
    };
    const res = await this.send(httpClient, ctx, req);
    return String(res?.data ?? '');
  }

  /**
   * 存储前 GET actionUrl 重抓 CSRF token（best-effort）：
   * 解析页面表单取 csrfTokenName 对应新值，覆盖 point.formValues；解析失败保留原 token。
   * @param {object} httpClient 统一 HttpClient
   * @param {object} ctx 检测上下文（含 point / config）
   */
  async _refreshCsrf(httpClient, ctx) {
    const point = ctx.point;
    if (!point.actionUrl || !point.csrfTokenName) return; // 无 action / 无 token 则跳过
    try {
      const res = await httpClient.request({
        method: 'GET',
        url: point.actionUrl,
        timeoutMs: ctx.config?.timeoutMs,
        retry: ctx.config?.retry,
        proxy: ctx.config?.proxy ?? false,
        auth: ctx.config?.auth ?? null,
        wafEvasion: ctx.config?.wafEvasion ?? null,
      });
      const html = String(res?.data ?? '');
      const forms = this._parseFormsForToken(html, point.actionUrl);
      const token = forms.length ? forms[0][point.csrfTokenName] : null;
      if (token != null && point.formValues) {
        point.formValues = { ...point.formValues, [point.csrfTokenName]: token };
      }
    } catch {
      /* best-effort：重抓失败保留原 token，不阻断存储 */
    }
  }

  // 轻量解析某 actionUrl 页面的表单，返回 { fieldName: value } 数组（仅取首个匹配）。
  // 复用 TargetParser 思路：取所有 <input> 的 name/value。
  _parseFormsForToken(html, baseUrl) {
    void baseUrl; // 此处仅取字段值，不解析 action，故 baseUrl 未使用
    const out = [];
    const formRe = /<form\b([^>]*)>([\s\S]*?)<\/form>/gi;
    let fm;
    while ((fm = formRe.exec(html))) {
      const inner = fm[2] || '';
      const values = {};
      const inputRe = /<input\b([^>]*)\/?>/gi;
      let im;
      while ((im = inputRe.exec(inner))) {
        const tag = im[1] || '';
        const name = this._attr(tag, 'name');
        if (!name) continue;
        const value = this._attr(tag, 'value') || '';
        values[name] = value;
      }
      out.push(values);
    }
    return out;
  }

  // 从标签字符串中取某属性值（兼容双引号/单引号/无引号）
  _attr(tag, name) {
    const re = new RegExp(`${name}\\s*=\\s*("([^"]*)"|'([^']*)'|([^\\s>]*))`, 'i');
    const m = tag.match(re);
    if (!m) return '';
    return m[2] !== undefined ? m[2] : m[3] !== undefined ? m[3] : m[4] !== undefined ? m[4] : '';
  }
}

export default SecondOrderDetector;
