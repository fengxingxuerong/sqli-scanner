import { nanoid } from 'nanoid';
import { Detector } from '../Detector.js';
import { createDetectionResult } from '../models.js';
import { PAYLOADS, SECOND_ORDER_PROBES, SECOND_ORDER_OOB_PROBES, ERROR_SIG, fillPayload } from '../payloads.js';
import { oobReceiver } from '../../core/oobReceiver.js';
import { ErrorCode, AppError } from '../../core/errors.js';
// P1-11 收敛：表单/标签属性解析与 TargetParser/crawler 共用单一事实源（含正则缓存）
import { attrValue } from '../crawler.js';

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
    const { httpClient, point, dbms, config, triggerUrl } = ctx;
    const result = createDetectionResult(point.id, 'second_order');

    // 无触发页 → 无法判定，直接未命中（不发起任何请求）
    if (!triggerUrl) return result;

    const so = (config && config.secondOrder) || {};
    if (!so.enabled) {
      // 防御性：编排层已门控，但直达 detect 时也应拒绝（避免误对目标发起写请求）
      throw new AppError(ErrorCode.SECOND_ORDER_DISABLED, '二阶检测未启用');
    }

    // OOB 触发分支：仅当显式开启 oobTrigger 且 oob 启用时走带外判定（触发页无回显场景）；
    // 否则走下方报错回显老路径（向后兼容，行为与现状完全一致）。
    const oobEnabled = !!(config && config.oob && config.oob.enabled);
    if (so.oobTrigger === true && oobEnabled) {
      return this._detectOob(ctx, result, so);
    }

    // 1) 基线：只读触发页，记录是否本就含报错特征（不写）
    const baselineBody = await this._trigger(httpClient, ctx, triggerUrl);
    const baselineErr = ERROR_SIG.test(baselineBody);

    // 2) 存储阶段（真实写）：构造报错探针 → 可选刷新 CSRF → POST 表单点
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
   * 二阶 OOB 触发判定：当触发页无回显时，存储探针改为嵌入"数据库带外回调"语句（OOB 外带）。
   * 触发页若执行了该 SQL，会向接收端发起 DNS/HTTP 回连，从而确认二阶注入。
   * 复用一阶 OOB 的标记生成 + 轮询机制（receiver.waitForToken），收到含该标记的回调即判定命中。
   * @param {object} ctx 检测上下文（含 config.oob / triggerUrl，可经 ctx.oobReceiver 注入假接收端供测试）
   * @param {object} result 未命中初始态 DetectionResult
   * @param {object} so config.secondOrder
   * @returns {Promise<import('../models.js').DetectionResult>}
   */
  async _detectOob(ctx, result, so) {
    const { httpClient, point, dbms, config, triggerUrl } = ctx;
    const oobCfg = (config && config.oob) || {};
    // P2-13: 未显式配置 callbackBase 时按接收端 httpPort 派生，避免回连打到旧端口
    const httpPort = Number(oobCfg.httpPort);
    const callbackBase =
      (typeof oobCfg.callbackBase === 'string' && oobCfg.callbackBase.trim() !== ''
        ? oobCfg.callbackBase
        : Number.isFinite(httpPort) && httpPort > 0
          ? `127.0.0.1:${httpPort}`
          : '127.0.0.1:8899');
    const timeoutMs = Number.isFinite(oobCfg.timeoutMs) ? oobCfg.timeoutMs : 5000;
    // 接收端：测试可经 ctx.oobReceiver 注入假接收端；生产用全局单例（与一阶 OobDetector 一致）
    const receiver = ctx.oobReceiver || oobReceiver;
    if (receiver === oobReceiver && !oobReceiver.isStarted()) {
      throw new AppError(ErrorCode.OOB_DISABLED, 'oob 接收端未启动（二阶 OOB 触发需 oob 启用且接收端就绪）');
    }

    // 唯一标记：scanId + pointId + 时间戳哈希 + 随机段，避免跨扫描/跨点误判
    const token = this._buildOobToken(ctx);
    const callback = `${callbackBase}/oob/${token}`;

    // 候选库：已知 dbms 且有二阶 OOB 探针 → 仅该库；否则遍历所有支持库逐一尝试
    const candidates = this._oobCandidates(dbms);

    // 存储前可选刷新 CSRF（与报错路径一致，best-effort）
    if (so.refreshCsrf) {
      await this._refreshCsrf(httpClient, ctx);
    }

    const stored = [];
    for (const cdb of candidates) {
      for (const tpl of SECOND_ORDER_OOB_PROBES[cdb] || []) {
        // OOB 探针不做 tamper（会破坏回调地址导致回连失败，与一阶 OobDetector 一致）
        const probe = fillPayload(tpl, { orig: point.originalValue || '1' }).replaceAll('{CALLBACK}', callback);
        await this._store(httpClient, ctx, probe);
        stored.push(probe);
        // 触发页读取出最新存储值并执行（若命中则向接收端回连）
        await this._trigger(httpClient, ctx, triggerUrl);
      }
    }

    // 轮询等待带外回连（迟到/重复回调亦判定命中）
    const hit = await receiver.waitForToken(token, timeoutMs);
    if (hit) {
      result.vulnerable = true;
      result.dbms = dbms || null;
      result.evidence =
        `二阶注入确认（OOB 外带）：存储探针后被触发页 ${triggerUrl} 读出并执行，数据库经带外通道回连 ` +
        `接收端 ${callbackBase}（token=${token}），确认存储点 ${point.param}@${point.actionUrl} 存在二阶注入`;
      result.payloads = stored;
      point.confirmed = true;
      point.technique = 'second_order';
      point.dbms = dbms || point.dbms;
    }
    return result;
  }

  /**
   * 生成二阶 OOB 唯一标记：scanId + pointId + 时间戳哈希 + 随机段，避免跨扫描/跨点误判。
   * 标记仅含 [A-Za-z0-9_-]（URL 路径安全，便于测试与回连匹配）。
   * @param {object} ctx 检测上下文（含 scanId / point.id）
   * @returns {string} 唯一标记
   */
  _buildOobToken(ctx) {
    const scanId = String(ctx.scanId || 'noscan').replace(/[^A-Za-z0-9_-]/g, '');
    const pointId = String((ctx.point && ctx.point.id) || 'nopoint').replace(/[^A-Za-z0-9_-]/g, '');
    const ts = Date.now().toString(36); // 时间戳哈希（36 进制）
    return `${scanId}_${pointId}_${ts}_${nanoid(10)}`;
  }

  /**
   * 二阶 OOB 候选库：已知 dbms 且有探针 → 仅该库；否则返回全部含探针的库（顺序即优先级）。
   * @param {string} dbms 已知数据库类型（可空）
   * @returns {string[]}
   */
  _oobCandidates(dbms) {
    if (dbms && Array.isArray(SECOND_ORDER_OOB_PROBES[dbms]) && SECOND_ORDER_OOB_PROBES[dbms].length) {
      return [dbms];
    }
    return Object.keys(SECOND_ORDER_OOB_PROBES).filter(
      (k) => Array.isArray(SECOND_ORDER_OOB_PROBES[k]) && SECOND_ORDER_OOB_PROBES[k].length > 0
    );
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
   * 触发阶段：读取触发页，返回响应体字符串（经统一 HttpClient）。
   * [sqlmap 对标] --second-url：当 config.secondOrder.secondUrl 非空时，读取请求发往
   * secondUrl（而非传入的 url），使用 secondMethod / secondData 构造请求。
   * secondUrl 为空时沿用传入 url（保持现有行为）。
   * @param {object} httpClient 统一 HttpClient
   * @param {object} ctx 检测上下文（含 target / config）
   * @param {string} url 触发页 URL（secondUrl 为空时的回退）
   * @returns {Promise<string>}
   */
  async _trigger(httpClient, ctx, url) {
    const so = (ctx.config && ctx.config.secondOrder) || {};
    // --second-url：读写分离场景，读取发往独立的 secondUrl
    const readUrl = so.secondUrl || url;
    const method = so.secondMethod || 'GET';
    const req = {
      method,
      url: readUrl,
      params: {},
      data: so.secondData != null ? so.secondData : {},
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
  // P1-11 收敛：委托 crawler.attrValue（与 TargetParser 共用单一事实源），消除逐字拷贝。
  _attr(tag, name) {
    return attrValue(tag, name);
  }
}

export default SecondOrderDetector;
