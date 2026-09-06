import { Detector } from '../Detector.js';
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
      const base = await this.send(httpClient, ctx, this.buildRequest(target, point, reqs.base));
      const test = await this.send(httpClient, ctx, this.buildRequest(target, point, reqs.test));

      const baseBody = String(base?.data ?? '');
      const testBody = String(test?.data ?? '');

      // 命中条件：测试响应含内联标记，且基线响应不含（排除"标记本来就出现在正常页面"的误报）
      // D6: includes 改为大小写不敏感，免疫 lowercase/uppercase/mixedcase tamper 破坏标记
      if (testBody.toLowerCase().includes(INLINE_MARKER.toLowerCase()) &&
          !baseBody.toLowerCase().includes(INLINE_MARKER.toLowerCase())) {
        // ★FIX [误报防护] 反射门控（对标 UnionDetector._gateInjection）：
        // 回显型页面会把任意输入原样返回——上面的命中条件对它恒真（标记字面量随注入串被反射）。
        // 补一发纯文本探针（不经 SQL 求值）：若同样被回显，说明只是参数反射而非子查询结果 → 拒绝。
        const refl = await this.send(httpClient, ctx, this.buildRequest(target, point, REFLECTION_PROBE));
        const reflBody = String(refl?.data ?? '');
        if (reflBody.toLowerCase().includes(REFLECTION_PROBE.toLowerCase())) {
          result.evidence =
            '内联候选被反射门控拒绝：纯文本探针同样回显，标记来自输入反射而非 SQL 子查询求值';
          return result;
        }
        return this._hit(result, point, `${reqs.test} → 子查询结果随响应回显（内联通道可用）`, [reqs.test]);
      }
      return result;
    } catch (e) {
      return result; // 单次失败不致命
    }
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
