import { Detector } from '../Detector.js';
import { createDetectionResult } from '../models.js';
import { PAYLOADS, fillPayload, ERROR_SIG } from '../payloads.js';

// 报错注入检测器
// 思路：注入会触发数据库报错的 Payload，检测响应中是否出现数据库报错特征
export class ErrorDetector extends Detector {
  constructor() {
    super('error');
  }

  /**
   * @param {object} ctx { httpClient, target, point, dbms, config }
   * @returns {Promise<import('../models.js').DetectionResult>}
   */
  async detect(ctx) {
    const { httpClient, target, point, dbms } = ctx;
    const result = createDetectionResult(point.id, 'error');

    // 基线：先确认原始请求是否本就含报错特征，避免把页面固有报错误判为注入
    const baseRes = await this.send(
      httpClient,
      ctx,
      this.buildRequest(target, point, point.originalValue || '1'),
      ctx
    );
    const baseBody = String(baseRes?.data ?? '');
    const baseMatch = baseBody.match(ERROR_SIG);

    // 优先使用命中库专属报错 Payload，否则遍历全部库的报错 Payload
    const templates =
      (PAYLOADS[dbms] && PAYLOADS[dbms].error) ||
      Object.values(PAYLOADS).flatMap((t) => t.error);

    for (const tpl of templates) {
      const filled = fillPayload(tpl, { orig: point.originalValue || '1' });
      const payload = this.obfuscateValue(ctx, filled);
      const res = await this.send(httpClient, ctx, this.buildRequest(target, point, payload), ctx);
      const body = String(res?.data ?? '');
      const match = body.match(ERROR_SIG);
      if (!match) continue;
      // 基线已存在同样的报错信息 → 视为页面固有，不计入注入
      if (baseMatch && match[0] === baseMatch[0]) continue;
      // 二次确认：再发一次，报错应稳定出现，过滤偶发噪声
      const res2 = await this.send(httpClient, ctx, this.buildRequest(target, point, payload), ctx);
      const body2 = String(res2?.data ?? '');
      if (!body2.match(ERROR_SIG)) continue;
      result.vulnerable = true;
      result.dbms = dbms;
      result.evidence = `数据库报错回显：${match[0]}`;
      result.payloads = [payload];
      point.confirmed = true;
      point.technique = 'error';
      point.dbms = dbms;
      break;
    }
    return result;
  }
}

export default ErrorDetector;
