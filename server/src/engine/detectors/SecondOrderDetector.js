import { nanoid } from 'nanoid';
import { Detector } from '../Detector.js';

// DNS 单个标签上限（RFC 1035 §2.3.4）。
// OOB token 会作为子域标签回连，超长会导致「有回连但精确匹配不上」的静默漏报，
// 故在 token 生成处显式约束 —— 见 _buildOobToken 的 [DNS-LABEL-FIX] 说明。
const MAX_DNS_LABEL = 63;
// [P0-FIX 2026-09-09] 二阶方法白名单 + 出口选项同源
import { resolveSecondOrderMethod } from '../secondOrderMethod.js';
import { buildEgressOpts } from '../egressOpts.js';
import { logger } from '../../core/logger.js';
import { createDetectionResult } from '../models.js';
import {
  PAYLOADS,
  SECOND_ORDER_PROBES,
  SECOND_ORDER_OOB_PROBES,
  ERROR_SIG,
  fillPayload,
  replaceAllLiteral,
} from '../payloads.js';
// [实战分析 P1 2026-10-02] 二阶 OOB 的 UNC/SMB 向量与一阶共用同一派生（裸主机 + share 名）
import { deriveUncPath } from './OobDetector.js';
import { oobReceiver } from '../../core/oobReceiver.js';
import { ErrorCode, AppError } from '../../core/errors.js';
// P1-11 收敛：表单/标签属性解析与 TargetParser/crawler 共用单一事实源（含正则缓存）
import { attrValue } from '../crawler.js';
// [P1-PERF 2026-11-02] 大响应有界匹配
import { matchBounded } from '../../core/boundedMatch.js';

/**
 * [D301 GAP②] 布尔差异判定的内容归一器：剥掉「同一请求两次读取本就会变」的易变内容，
 * 只留稳定骨架。与 services/reproPack.js 的 stripVolatile 语义对齐（剔 10 位以上长数字 /
 * ISO 时间戳），另加 HTML 注释剥离（DVWA/lab 页面的 `<!-- generated at … -->` 水印）与
 * 空白折叠。刻意不内联进 _maybeDiffJudge：保持判定函数行数/复杂度远离硬上限。
 * @param {string|null|undefined} body 触发页响应体（D302 起 diffJudge 复用阴性读，未开阴性对照时为 null）
 * @returns {string} 归一化文本（空体 → 空串，调用方以 !p1 视为「不稳定/无内容」）
 */
function _normForDiff(body) {
  return String(body ?? '')
    .replace(/<!--[\s\S]*?-->/g, '')
    .replace(/\d{10,}/g, '')
    .replace(/\d{4}-\d{2}-\d{2}(T[\d:.]+Z?)?/g, '')
    .replace(/\s+/g, ' ')
    .trim();
}

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
    super('second_order', { match: 'stored', extract: ['dbms'] });
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

    // 1) 基线：只读触发页，记录是否本就含报错特征（不写）。
    //    记录报错指纹（命中的具体文本）而非仅布尔：触发页可能自带固有报错
    //    （如空参数语法错误），此时需对比「报错内容是否因存储探针而变化」。
    const baselineBody = await this._trigger(httpClient, ctx, triggerUrl);
    const baseMatch = matchBounded(baselineBody, ERROR_SIG);
    const baselineErr = !!baseMatch;

    // 2) 存储阶段（真实写）：构造报错探针 → 可选刷新 CSRF → POST 表单点
    const probe = this._buildProbe(ctx, dbms);
    if (so.refreshCsrf) {
      await this._refreshCsrf(httpClient, ctx); // GET actionUrl 重抓 token 覆盖 formValues（best-effort）
    }
    await this._store(httpClient, ctx, probe);

    // 3) 触发阶段：读触发页，看是否回显报错
    const expBody = await this._trigger(httpClient, ctx, triggerUrl);
    const expMatch = matchBounded(expBody, ERROR_SIG);
    const expErr = !!expMatch;

    // 4) 阴性对照（可选）：存良性值 → 读触发页应无报错（提高判定置信）
    // [D302] negBody 提升到函数级：diffJudge 复验把它当第一次阴性读（省 1 写 1 读）
    let negErr = false; let negBody = null;
    let negMatch = null;
    if (so.negativeControl) {
      const benign = point.originalValue && String(point.originalValue).trim() ? point.originalValue : 'benign';
      await this._store(httpClient, ctx, benign);
      negBody = await this._trigger(httpClient, ctx, triggerUrl);
      negMatch = matchBounded(negBody, ERROR_SIG);
      negErr = !!negMatch;
    }

    // 5) 判定（双路径）：
    //    路径 A（基线干净，原三态）：基线无报错 && 实验有报错 && 阴性无报错。
    //    路径 B（基线即报错，[P1-FIX 2026-09-07]）：触发页自带固有报错（空参数语法错误、
    //      上游故障等真实场景常见），此时以「报错指纹」判定——存储探针后报错内容变化
    //      （expMatch ≠ baseMatch）说明存储值确实改写了被拼入的 SQL；阴性对照存良性值后
    //      报错恢复基线指纹（negMatch === baseMatch）排除环境噪声。阴性对照未开启时
    //      不判定（保守：无法区分固有噪声与注入信号，宁可漏报不误报）。
    let hit = false;
    if (!baselineErr && expErr && !negErr) {
      hit = true;
    } else if (baselineErr && expErr) {
      hit =
        so.negativeControl === true &&
        expMatch[0] !== baseMatch[0] &&
        negMatch != null &&
        negMatch[0] === baseMatch[0];
    }
    if (hit) {
      result.vulnerable = true;
      result.dbms = dbms || null;
      result.evidence = !baselineErr
        ? `二阶注入确认：存储探针后在触发页 ${triggerUrl} 回显数据库报错（基线无、实验有、阴性无），` +
          `存储点 ${point.param}@${point.actionUrl} 的数据被读出后重新拼入查询触发注入`
        : `二阶注入确认（基线噪声路径）：触发页 ${triggerUrl} 固有报错「${baseMatch[0]}」，存储探针后报错变化为「${expMatch?.[0] ?? ''}」，` +
          `阴性对照恢复基线报错——存储点 ${point.param}@${point.actionUrl} 的数据被读出后改写了查询行为`;
      result.payloads = [probe];
      point.confirmed = true;
      point.technique = 'second_order';
      point.dbms = dbms || point.dbms;
    }
    // [D301 GAP②] 签名判定未命中时，opt-in 布尔差异判定（报错抑制型触发页的唯一出路）。
    // 平换末行的原因：detect 在复杂度基线里（57 行/25 圈 = 硬上限），行数与分支数零变化。
    // [D302] 透传 negBody：签名阶段的阴性读即 diff 判定的第一次阴性读（省 1 写 1 读）。
    return this._maybeDiffJudge(httpClient, ctx, result, so, probe, expBody, negBody);
  }

  /**
   * [D301 GAP②] 布尔差异判定（报错抑制型触发页）。
   * 背景（DVWA sqli high 实证）：high.php 把 mysqli 报错抑制为 "Something went wrong."，
   * ERROR_SIG 签名判定永远不可见 ⇒ 二阶检测静默漏报。本路径在签名未命中且显式
   * opt-in（secondOrder.diffJudge === true）时启用：探针页与阴性对照页各再读一次，
   * 「剔除易变内容后」两两必须稳定一致（动态页面噪声被第二次读取排除），且探针页
   * 与阴性页必须存在内容差异——三重防误报（稳定性×2 + 差异存在性），宁漏不误。
   * 为什么不复用 services/reproPack 的 normalizeForCompare：引擎层不反向依赖服务层
   * （架构守卫口径），此处 6 行本地归一器与 stripVolatile 语义对齐（剔长数字/注释/空白）。
   * @param {object} httpClient 统一 HttpClient
   * @param {object} ctx 检测上下文（含 point / config / triggerUrl / dbms）
   * @param {object} result 检测结果（可变；签名路径已命中时本方法直接返回）
   * @param {object} so config.secondOrder（diffJudge/negativeControl 闸）
   * @param {string} probe 已存储过的报错探针（本方法会原样再存一次做稳定性复验）
   * @param {string} expBody 签名阶段探针存储后的触发页响应（第一次探针读）
   * @param {string|null} negBody 签名阶段阴性存储后的触发页响应（第一次阴性读；未开阴性对照时为 null）
   * @returns {Promise<object>} result（可能被置 vulnerable=true）
   */
  async _maybeDiffJudge(httpClient, ctx, result, so, probe, expBody, negBody) {
    if (result.vulnerable || !so || so.diffJudge !== true || !so.negativeControl) return result;
    const benign = ctx.point?.originalValue && String(ctx.point.originalValue).trim()
      ? String(ctx.point.originalValue)
      : 'benign';
    // [D302] 稳定性复验省请求：签名阶段的 expBody/negBody 即第一次读，这里各补一次
    //（探针复验 1 写 1 读 + 阴性复验 1 写 1 读），比 D301 版省 1 写 1 读。
    await this._store(httpClient, ctx, probe);
    const probe2 = await this._trigger(httpClient, ctx, ctx.triggerUrl);
    await this._store(httpClient, ctx, benign);
    const neg2 = await this._trigger(httpClient, ctx, ctx.triggerUrl);
    const p1 = _normForDiff(expBody);
    const p2 = _normForDiff(probe2);
    const n1 = _normForDiff(negBody);
    const n2 = _normForDiff(neg2);
    if (!p1 || p1 !== p2) {
      logger.info('[second-order] 布尔差异判定：探针页两次读取不一致（动态页面噪声），放弃判定（宁漏不误）');
      return result;
    }
    if (!n1 || n1 !== n2) {
      logger.info('[second-order] 布尔差异判定：阴性对照页两次读取不一致，放弃判定（宁漏不误）');
      return result;
    }
    if (p1 === n1) return result; // 探针页与阴性页无内容差异：无注入信号
    result.vulnerable = true;
    result.dbms = ctx.dbms || null;
    result.evidence = `二阶注入确认（布尔差异路径 [D301]）：存储点 ${ctx.point?.param}@${ctx.point?.actionUrl} 的探针值改写了触发页查询行为——` +
      `探针页两次读取稳定一致且与阴性对照页存在内容差异（触发页 ${ctx.triggerUrl}；报错被目标抑制，签名判定不可见）`;
    result.payloads = [probe];
    ctx.point.confirmed = true;
    ctx.point.technique = 'second_order';
    ctx.point.dbms = ctx.dbms || ctx.point.dbms;
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
        // OOB 探针不做 tamper（会破坏回调地址导致回连失败，与一阶 OobDetector 一致）。
        // [实战分析 P1 2026-10-02] UNC/SMB 类向量填 {UNC}（裸主机 + share 名，不带端口；
        // 与一阶 OobDetector.deriveUncPath 同一派生），HTTP 类向量照旧填 {CALLBACK}。
        const probe = replaceAllLiteral(
          replaceAllLiteral(
            fillPayload(tpl, { orig: point.originalValue || '1' }),
            '{CALLBACK}',
            callback
          ),
          '{UNC}',
          deriveUncPath(callbackBase, token)
        );
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
    // [DNS-LABEL-FIX 2026-09-21] DNS 单个标签上限 **63 字节**（RFC 1035 §2.3.4）。
    // 本 token 会被拼成 `{CALLBACK}` 的子域名（见 _detectOob），而接收端 _handleDns
    // **只取第一个标签**当 token、waitForToken 又是**精确匹配**：
    //   若 token 超 63 字节 → 目标端 DNS 库要么拒绝发送该查询，要么被拆/截成第一个标签
    //   → 收到的字符串永远不等于完整 token → **静默漏报**（有回连却判未命中）。
    // 此前无任何长度约束（grep `63` 在 oobReceiver / OobDetector / 本文件零命中）。
    // 一阶 OobDetector 用 nanoid(16) 天然安全；二阶把 scanId+pointId+ts 串起来，长度
    // 取决于上游 id 格式（scanId 现为 nanoid(12)），实测约 41，但**无约束即无保证**。
    const full = `${scanId}_${pointId}_${ts}_${nanoid(10)}`;
    if (full.length <= MAX_DNS_LABEL) return full;
    // 超长：优先保住唯一性来源（时间戳 + 随机段），长 id 退化为片段（仅便于人读定位）
    const tail = `${ts}_${nanoid(10)}`;
    const head = `${scanId}_${pointId}`.slice(0, Math.max(1, MAX_DNS_LABEL - tail.length - 1));
    return `${head}_${tail}`;
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
    // [todo#39] 跨角色触发：存储阶段使用 storeCookies 指定身份（低权写入方）。
    // 显式配置的同名 Cookie 优先（同名不覆盖），target.cookieParams 会话合并补充——
    // 与 _trigger 的 Cookie 合并语义一致，未配置 storeCookies 时行为零变化。
    const soCookies = (ctx.config && ctx.config.secondOrder && ctx.config.secondOrder.storeCookies) || null;
    if (soCookies && typeof soCookies === 'object') {
      const headers = { ...(req.headers || {}) };
      const existing = Object.keys(headers).find((k) => k.toLowerCase() === 'cookie');
      const sessPairs = Object.entries(ctx.target.cookieParams || {});
      const explicitPairs = Object.entries(soCookies);
      if (existing) {
        const names = new Set(String(headers[existing]).split(';').map((p) => p.split('=')[0].trim()));
        const extra = [...explicitPairs, ...sessPairs].filter(([k]) => !names.has(k));
        if (extra.length) headers[existing] = `${headers[existing]}; ${extra.map((p) => p.join('=')).join('; ')}`;
      } else {
        const merged = [...explicitPairs, ...sessPairs.filter(([k]) => !(k in soCookies))];
        if (merged.length) headers['Cookie'] = merged.map((p) => p.join('=')).join('; ');
      }
      req.headers = headers;
    }
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
    // [D42 2026-10-11 对标 sqlmap --second-req] 整请求形态的触发页（CLI/REST 组装自 -r 同源
    // 解析器）：URL/method/headers/body 整体来自用户抓包。优先级高于 secondUrl/secondMethod/
    // secondData（抓包是用户显式给的完整意图）；幂等门照走 resolveSecondOrderMethod，
    // 会话 cookie 合并照做（抓包 Cookie 优先，会话补缺失键——与 headerParams 同优先级语义）。
    const tr = so.triggerRequest && typeof so.triggerRequest === 'object' && typeof so.triggerRequest.url === 'string'
      ? so.triggerRequest
      : null;
    // --second-url：读写分离场景，读取发往独立的 secondUrl
    const readUrl = tr ? tr.url : (so.secondUrl || url);
    // [P0-FIX 2026-09-09] 触发读请求的方法必须过白名单与幂等门。旧写法 `so.secondMethod || 'GET'`
    // 把用户字符串直送 HTTP 层（TRACE/CONNECT/含 CRLF 均照发）；而「只读复核」在 productionMode 下
    // 只对 GET/HEAD 成立——非幂等方法必须 secondOrder.allowWrites=true 才放行。
    const trig = resolveSecondOrderMethod(tr ? tr.method : so.secondMethod, {
      productionMode: ctx.config?.productionMode,
      allowWrites: so.allowWrites,
    });
    if (trig.skipped) {
      logger.warn(`二阶触发读请求已抑制：${trig.reason}`);
      return '';
    }
    if (trig.reason) logger.warn(`二阶配置修正：${trig.reason}`);
    const method = trig.method;
    // [P0-FIX 2026-09-06] 触发页请求带上 target.cookieParams 会话：触发页常为 requireAuth
    // 页面（如 /panel），不带会话 → 401 未登录页 → 永远无报错回显 → 二阶必漏（real-world-lab 实测）。
    // 用户显式 headerParams 的 Cookie 优先（同名不覆盖），会话 cookie 合并补充。
    const headers = tr && tr.headers && typeof tr.headers === 'object'
      ? { ...tr.headers }
      : { ...(ctx.target.headerParams || {}) };
    const sessCookies = ctx.target.cookieParams || {};
    // [todo#39] 跨角色触发：触发页读取使用 triggerCookies 指定身份（高权读出方）。
    // 优先级：用户显式 headerParams Cookie > triggerCookies > 会话 cookieParams 合并补充。
    const roleCookies = so.triggerCookies && typeof so.triggerCookies === 'object' ? so.triggerCookies : null;
    if (Object.keys(sessCookies).length || roleCookies) {
      const existing = Object.keys(headers).find((k) => k.toLowerCase() === 'cookie');
      const sessPairs = Object.entries(sessCookies);
      const rolePairs = roleCookies ? Object.entries(roleCookies) : [];
      if (existing) {
        const names = new Set(String(headers[existing]).split(';').map((p) => p.split('=')[0].trim()));
        const extra = [...rolePairs, ...sessPairs].filter(([k]) => !names.has(k));
        if (extra.length) headers[existing] = `${headers[existing]}; ${extra.map((p) => p.join('=')).join('; ')}`;
      } else {
        const merged = [...rolePairs, ...sessPairs.filter(([k]) => !(roleCookies && k in roleCookies))];
        if (merged.length) headers['Cookie'] = merged.map((p) => p.join('=')).join('; ');
      }
    }
    const req = {
      method,
      url: readUrl,
      params: {},
      data: tr
        ? (tr.body != null && tr.body !== '' ? tr.body : {})
        : (so.secondData != null ? so.secondData : {}),
      headers,
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
      // [P0-FIX 2026-09-09] 不再手拄出口选项（这里是第四份副本）：漏一个键就是「重抓 CSRF 时
      // 不看会话 / 不走代理 / 不理 cookieJar」，而 CSRF 刷新失败会让后面每个存储请求都 403，
      // 现场只看到「二阶无回显」，极难归因。
      const res = await httpClient.request(
        buildEgressOpts(ctx.config || {}, { method: 'GET', url: point.actionUrl })
      );
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
