import { Detector } from '../Detector.js';
import { logger } from '../../core/logger.js';
import { createDetectionResult } from '../models.js';
import { INLINE_CONCAT, fromDummy } from '../DialectSqlBuilder.js';

// 内联查询检测器（对标 sqlmap --technique=Q）
//
// 技术本质：把标量子查询直接注入参数值位置，若目标把"SQL 求值后的结果"回显到响应
// （即存在"回显点"：查询某列被输出、且注入值能进入该列），则子查询结果随响应带出。
// 这是 sqlmap `Q` 的核心使用场景（无需 UNION 即可就地提值）。
//
// 架构边界（诚实声明，详见 docs/technique_inline_oob_tradeoff.md）：
//   - 完整内联"拖库"要求重建原始 SQL 模板并把子查询注入 SELECT 列表；本工具是单参数注入模型，
//     不做查询模板重建，故"逐表内联拖库"暂未实现，提取复用既有的 UNION / 字节级盲注通道。
//   - 本检测器实现的是 `Q` 的**检测半**：确认"子查询执行通道 + 回显点"存在（注入含标记的
//     子查询后，标记随响应回显即命中）。这是布尔/联合之外独立可确认的一类证据，opt-in 开启。
//
// 非破坏性：仅注入 `SELECT '<MARKER>'` 这类只读子查询，不改写、不命令执行。
export class InlineQueryDetector extends Detector {
  constructor() {
    super('inline'); // technique 标记 'inline'（对标 sqlmap 字母 Q）
  }

  /**
   * @param {object} ctx { httpClient, target, point, config, dbms }
   * @returns {Promise<import('../models.js').DetectionResult>}
   */
  async detect(ctx) {
    const { httpClient, target, point, dbms } = ctx;
    const result = createDetectionResult(point.id, 'inline');

    const db = resolveInlineDbms(dbms || point.dbms);
    // 仅对支持标量子查询的关系型 DBMS 尝试（SQLite 也支持，但回显点场景少，仍纳入）
    if (!db) return result;

    const reqs = this._build(point, db);
    if (!reqs) return result;

    try {
      // [P0-FIX 2026-10-05] 基线与测试同样先判可用性：
      // 折成空串时 `!baseBody.includes(MARK)` 恒真 ⇒ 页面固有标记这条防线
      // （契约-5）被绕过。基线不可用时同样无法区分"固有标记"与"反射"。
      const base = await this._sendUsable(httpClient, ctx, target, point, reqs.base);
      const test = await this._sendUsable(httpClient, ctx, target, point, reqs.test);
      if (base === null || test === null) {
        result.evidence = '内联探测未结论：基线或测试响应不可用（网络失败，重发后仍失败）';
        return result;
      }

      const baseBody = String(base.data ?? '');
      const testBody = String(test.data ?? '');

      // 命中条件：测试响应含内联标记，且基线响应不含（排除"标记本来就出现在正常页面"的误报）
      // D6: includes 改为大小写不敏感，免疫 lowercase/uppercase/mixedcase tamper 破坏标记
      if (testBody.toLowerCase().includes(INLINE_MARKER.toLowerCase()) &&
          !baseBody.toLowerCase().includes(INLINE_MARKER.toLowerCase())) {
        // ★FIX [误报防护] 反射门控（对标 UnionDetector._gateInjection）：
        // 回显型页面会把任意输入原样返回——上面的命中条件对它恒真（标记字面量随注入串被反射）。
        // 补一发纯文本探针（不经 SQL 求值）：若同样被回显，说明只是参数反射而非子查询结果 → 拒绝。
        //
        // [P0-FIX 2026-10-05] 探针失败时不得当作"未反射"：
        // 原实现 String(refl?.data ?? '') 把网络失败折成空串，includes 恒 false
        // ⇒ 直接走 _hit 放行。方向与 Union/NoSQL 相反：**门控自身失败反而放行**，
        // 恰是门控最不该有的行为。实测：base 正常 + test 含标记 + 探针超时
        // ⇒ vulnerable=true，evidence 写「子查询结果随响应回显」。
        // 失败样本重发一次；仍失败则不产出结论（本条不算检出，也不算排除）。
        const refl = await this._sendUsable(httpClient, ctx, target, point, REFLECTION_PROBE);
        if (refl === null) {
          result.evidence =
            '内联探测未结论：反射门控探针不可用（网络失败，重发后仍失败），无法区分参数反射与子查询求值';
          return result;
        }
        const reflBody = String(refl.data ?? '');
        if (reflBody.toLowerCase().includes(REFLECTION_PROBE.toLowerCase())) {
          result.evidence =
            '内联候选被反射门控拒绝：纯文本探针同样回显，标记来自输入反射而非 SQL 子查询求值';
          return result;
        }
        return this._hit(result, point, `${reqs.test} → 子查询结果随响应回显（内联通道可用）`, [reqs.test]);
      }
      return result;
    } catch (e) {
      // [2026-10-05] 补 debug 日志：原先 `catch (e) { return result; }` 完全静默，
      // 连 e 都没用。后果是内联通道探测失败时，无法区分"目标真的不支持内联查询"
      // （合法负结论）与"我们的探测自己抛了"（假阴性）。
      // 扫描器里后者更贵：它会被写成"该点无内联通道"，用户据此判断后才决定换不换注入手法。
      // 用 debug 而非 warn：单点探测失败是常态（大量目标本就无内联），warn 会刷屏。
      // ⚠️ point 是个对象，直接插值会得到 `[object Object]`（注入验证时才发现），
      //   对定位毫无帮助 —— 必须打 point.id。
      logger.debug(`内联查询探测失败（按"该点无内联通道"处理）：point=${point?.id} err=${e?.message ?? e}`);
      return result;
    }
  }

  /**
   * [P0-FIX 2026-10-05] 发送请求并返回响应；不可用的重发一次。
   *
   * 缺陷：原先各处 `String((await this.send(...))?.data ?? '')` 把网络失败
   * 折成空串，空串对"是否包含标记"的判定一律给出安全但错误的方向：
   *   - 反射探针失败 ⇒ 判"未反射" ⇒ **放行**（误报，门控失败反而放行）
   *   - 基线失败     ⇒ 判"基线不含标记" ⇒ 绕过页面固有标记这道防线
   * 方向与 Union 门控、NoSQL 探测同源（未用统一判据 unusableOf），
   * 是本轮扫描找到的第三处遗漏。
   *
   * 失败后重发而非直接放弃：直接放弃会把假阳性修成假阴性，违反
   * 「不得降低检出能力」；重发可救回偶发抖动。
   *
   * @returns {Promise<object|null>} null = 重发后仍不可用，调用方应不下结论
   */
  async _sendUsable(httpClient, ctx, target, point, payload) {
    const req = this.buildRequest(target, point, payload);
    let res = await this.send(httpClient, ctx, req);
    if (!this.unusableOf(res)) return res;
    res = await this.send(httpClient, ctx, req);
    if (!this.unusableOf(res)) return res;
    return null;
  }

  _hit(result, point, evidence, payloads) {
    result.vulnerable = true;
    result.dbms = null; // 内联通道与具体 DBMS 解耦（子查询执行能力本身即证据）
    result.evidence = evidence;
    result.payloads = payloads;
    point.confirmed = true;
    point.technique = 'inline';
    return result;
  }

  /**
   * 构造 基线/测试 两态注入值。
   * 测试态：把"返回内联标记的子查询"注入值位置，期待其 SQL 求值结果随响应回显。
   * 占位符 {ORIG}=原始值；fromDual 仅 Oracle/DM8 需要。
   */
  _build(point, db) {
    const orig = (point && point.originalValue) || '1';
    const fromDual = fromDummy(db);
    const subq = `SELECT '${INLINE_MARKER}'${fromDual}`;

    // 数值型参数：值位置直接替换为 (子查询)，期待回显点把结果带出
    if (!isNaN(Number(orig))) {
      return { base: orig, test: `(${subq})` };
    }
    // 字符型参数：用 dbms 串接符把子查询结果拼到原值之后，期待整体回显
    // P2-22: INLINE_CONCAT 全是 '||'/'+' 无 CONCAT 前缀键，死分支已删
    const op = INLINE_CONCAT[db] || '||';
    const concatTest = `${orig}' ${op} (${subq}) ${op} ''`;
    return { base: orig, test: concatTest };
  }
}

// 内联回显标记（复用 Extractor 的 __S__/__E__ 包裹约定，便于提取阶段直接复用）
export const INLINE_MARKER = '__S__INL__E__';

// 反射门控探针：纯文本值，不经任何 SQL 求值。若目标把它原样回显，
// 说明该站是"输入反射型"响应，内联标记命中不可信（与 INLINE_MARKER 无公共子串，避免误判）。
const REFLECTION_PROBE = 'SQLISCANNER_REFL_7QZ4X';

// 归一化 dbms 到内联检测支持集合（未知/非关系型 → null 跳过）
function resolveInlineDbms(dbms) {
  if (!dbms) return 'MySQL'; // 未识别时按 MySQL 方言尝试（最宽泛，避免漏检）
  const m = String(dbms).toLowerCase();
  if (m.includes('oracle') || m.includes('dm8') || m.includes('dameng')) return 'Oracle';
  if (m.includes('postgre')) return 'PostgreSQL';
  if (m.includes('tidb')) return 'TiDB';
  if (m.includes('sql server') || m.includes('mssql')) return 'SQL Server';
  if (m.includes('maria')) return 'MariaDB';
  if (m.includes('sqlite')) return 'SQLite';
  if (m.includes('clickhouse')) return 'ClickHouse'; // ClickHouse 支持子查询，纳入尝试
  if (m.includes('mysql')) return 'MySQL';
  return 'MySQL';
}

export default InlineQueryDetector;
