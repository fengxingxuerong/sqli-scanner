import { Detector } from '../Detector.js';
import { createDetectionResult } from '../models.js';
import { NOSQL_OPERATOR_PROBES, SSTI_PROBES, GRAPHQL_PROBES } from '../payloads.js';
import { chunkSimilarity } from '../../core/statsHelper.js';

// 非 SQL 注入检测器（NoSQL / GraphQL / SSTI）
// 与经典 SQLi 检测器（union/error/boolean/time）正交：目标后端不是关系型 SQL 引擎，
// 经典 payload 对其无效，故不进入 ScanManager.detectors 一阶循环，避免对无此类后端的
// 目标产生大量噪音误报。作为独立补充趟（对标 second_order 编排）按需开启（opt-in）。
//
// 三类归入同一检测器，靠 ctx.noSqlKind 区分（'nosql' | 'graphql' | 'ssti'）：
//   - nosql：MongoDB 运算符注入（$gt/$ne/$where/$regex/$in/$nin/$exists/$type），布尔差异判定
//   - graphql：内省/字段别名/批处理/循环查询探测（__schema/__typename 回显）
//   - ssti：多模板引擎注入（Jinja2/FreeMarker/Velocity/ERB/Thymeleaf/通用），表达式求值回显
//
// 判定升级（对标经典布尔盲注统计思路，保持轻量）：
//   - 内容差异判定（真/假响应有实质内容差异，且与基线可区分），剔除纯长度噪声
//   - 二次确认：可疑命中换一组等价 payload 再测，两次一致才报，降低单次抖动误报
export class NoSqlInjectionDetector extends Detector {
  constructor() {
    super('nosql'); // technique 标记统一为 nosql（前端/报告维度归为一类"非SQL注入"）
  }

  /**
   * @param {object} ctx {
   *   httpClient, target, point, config,
   *   noSqlKind: 'nosql'|'graphql'|'ssti'  // ← 编排层注入，区分三类
   * }
   * @returns {Promise<import('../models.js').DetectionResult>}
   */
  async detect(ctx) {
    const { httpClient, target, point, noSqlKind } = ctx;
    const kind = noSqlKind || 'nosql';
    const result = createDetectionResult(point.id, 'nosql');
    result.noSqlKind = kind; // 透传子类，便于报告展示具体类别
    if (!['nosql', 'graphql', 'ssti'].includes(kind)) return result; // 未知类别 → 不投

    try {
      // 基线：原始值未注入（三类探测共同参照，供"与基线可区分"判定）
      const baseResp = await this.send(httpClient, ctx, this.buildRequest(target, point, point.originalValue || '1'));
      const baseBody = String(baseResp?.data ?? '');

      if (kind === 'ssti') return this._detectSsti(ctx, point, baseBody, result);
      if (kind === 'graphql') return this._detectGraphql(ctx, point, baseBody, result);
      return this._detectNosql(ctx, point, baseBody, result);
    } catch {
      // 单次失败不致命，标记未命中
      return result;
    }
  }

  _hit(result, point, kind, evidence, payloads) {
    result.vulnerable = true;
    result.dbms = null; // 非 SQL 注入无关系型 dbms
    result.noSqlKind = kind;
    result.evidence = evidence;
    result.payloads = payloads;
    point.confirmed = true;
    point.technique = 'nosql';
    point.noSqlKind = kind;
    return result;
  }

  /**
   * [P0-FIX 2026-10-05] 发送探针并取响应体；不可用的重发一次。
   *
   * 缺陷：原实现各处直接 `String((await this.send(...))?.data ?? '')`，
   * 把**网络失败**折成空串参与差异判定。实测（跑 _detectNosql，非推理）：
   *   真侧超时 + 假侧正常 → vulnerable=true，evidence 写「真长 0 ≠ 假长 17」
   *   真侧正常 + 假侧超时 → vulnerable=true，「真长 45 ≠ 假长 0」
   *   全部超时          → vulnerable=false（双边空串恰好相同，**巧合**正确）
   * 单边失败一律误报，且报告把「超时」写成「真条件返回空」——结论污染。
   *
   * 与 Union 门控同源（那里漏掉 unusableOf），口径统一在
   * egressOpts.isUnusableResponse（Detector.prototype.unusableOf 即其包装）。
   * BooleanBlind/TimeBlind/Stacked/prefilter 早已有这道闸，本类与 Union 是仅有的两处遗漏。
   *
   * 失败后**重发**而不是直接放弃：直接放弃会把假阳性修成假阴性，
   * 违反「不得降低检出能力」。重发仍失败才让该探针跳过（continue）。
   * 偶发抖动因此可被救回，纯失败则退化为「本次不报」，与原行为最接近。
   *
   * @returns {Promise<{body: string}|null>} null = 重发后仍不可用，调用方应跳过该探针
   */
  async _sendBody(httpClient, ctx, target, point, payload) {
    const req = this.buildRequest(target, point, payload);
    let res = await this.send(httpClient, ctx, req);
    if (!this.unusableOf(res)) return { body: String(res?.data ?? '') };
    res = await this.send(httpClient, ctx, req);
    if (!this.unusableOf(res)) return { body: String(res?.data ?? '') };
    return null;
  }

  /**
   * MongoDB 运算符注入：按成本升序遍历操作符矩阵（$gt/$ne 优先，命中即停），
   * 每组先发 primary 真/假，内容差异命中后再发 confirm 等价真/假做二次确认。
   */
  async _detectNosql(ctx, point, baseBody, result) {
    const { httpClient, target } = ctx;
    const orig = point.originalValue || '1';
    for (const probe of NOSQL_OPERATOR_PROBES) {
      const pTrue = this._nosqlPayload(orig, probe.primary.true);
      const pFalse = this._nosqlPayload(orig, probe.primary.false);
      // 失败样本不参与判定：单边失败会把「超时」误读成「真条件返回空」⇒ 直接误报。
      const t = await this._sendBody(httpClient, ctx, target, point, pTrue);
      if (t === null) continue;                       // 重发仍失败 → 跳过本探针
      const f = await this._sendBody(httpClient, ctx, target, point, pFalse);
      if (f === null) continue;
      const tBody = t.body, fBody = f.body;
      // 首轮：真/假需有实质内容差异，且至少其一与基线可区分
      if (!this._contentDiff(tBody, fBody)) continue;
      if (!this._distinctFromBase(tBody, fBody, baseBody)) continue;
      // 二次确认：换一组等价 payload（同操作符、不同取值），两次一致才报
      const cTrue = this._nosqlPayload(orig, probe.confirm.true);
      const cFalse = this._nosqlPayload(orig, probe.confirm.false);
      const ct = await this._sendBody(httpClient, ctx, target, point, cTrue);
      if (ct === null) continue;
      const cf = await this._sendBody(httpClient, ctx, target, point, cFalse);
      if (cf === null) continue;
      if (!this._contentDiff(ct.body, cf.body)) continue; // 确认不一致 → 视作抖动，弃
      return this._hit(
        result,
        point,
        'nosql',
        `NoSQL 运算符注入（${probe.name}）：真/假响应内容差异，二次确认一致（真长 ${tBody.length} ≠ 假长 ${fBody.length}，基线 ${baseBody.length}）`,
        [pTrue, pFalse, cTrue, cFalse]
      );
    }
    return result;
  }

  /**
   * SSTI：遍历多引擎探测表，表达式被求值（回显 sig 特征且基线不含）即命中，命中即停。
   */
  async _detectSsti(ctx, point, baseBody, result) {
    const { httpClient, target } = ctx;
    const orig = point.originalValue || '1';
    for (const probe of SSTI_PROBES) {
      const payload = `${orig}${probe.expr}`;
      // 同 _detectNosql：失败样本不参与判定（此处方向是漏报而非误报 ——
      // 空串必然匹配不上 sig，靠的是巧合而非判据；重发可挽回偶发失败）
      const r = await this._sendBody(httpClient, ctx, target, point, payload);
      if (r === null) continue;
      const body = r.body;
      // 求值判定：响应含 sig（49/config/<class> 等），且基线不含该特征（排除原样回显未求值）
      if (probe.sig.test(body) && !probe.sig.test(baseBody)) {
        return this._hit(result, point, 'ssti', `SSTI（${probe.engine}）：${probe.expr} 表达式被求值回显`, [payload]);
      }
    }
    return result;
  }

  /**
   * GraphQL：遍历内省/字段别名/批处理/循环查询探测表（只读，不写不执行），回显即命中。
   */
  async _detectGraphql(ctx, point, baseBody, result) {
    const { httpClient, target } = ctx;
    for (const probe of GRAPHQL_PROBES) {
      // 同上：失败样本不参与判定
      const r = await this._sendBody(httpClient, ctx, target, point, probe.query);
      if (r === null) continue;
      if (probe.sig.test(r.body) && !probe.sig.test(baseBody)) {
        return this._hit(result, point, 'graphql', `GraphQL 注入（${probe.name}）：${probe.query} → 回显确认`, [probe.query]);
      }
    }
    return result;
  }

  // 拼接 NoSQL 运算符注入串：闭合字符串上下文 + 操作符对象 + 注释（JSON body 与 URL 参数入口均兼容）
  _nosqlPayload(orig, operator) {
    return `${orig}', ${operator}]};//`;
  }

  /**
   * 内容差异判定：两响应体有实质内容差异（非纯长度噪声）。
   * 长度差显著（>8 且 >8%）直接判差异；长度接近时用分块相似度剔除「同内容仅长度微变」噪声。
   */
  _contentDiff(a, b) {
    const sa = String(a ?? '');
    const sb = String(b ?? '');
    if (sa === sb) return false;
    const la = sa.length;
    const lb = sb.length;
    if (Math.abs(la - lb) > Math.max(8, Math.max(la, lb) * 0.08)) return true;
    return chunkSimilarity(sa, sb, 32) < 0.95;
  }

  // 与基线可区分：真/假至少其一相对基线有实质内容差异（注入确实改变了页面语义，而非纯噪声）
  _distinctFromBase(tBody, fBody, baseBody) {
    return this._contentDiff(tBody, baseBody) || this._contentDiff(fBody, baseBody);
  }
}

export default NoSqlInjectionDetector;
