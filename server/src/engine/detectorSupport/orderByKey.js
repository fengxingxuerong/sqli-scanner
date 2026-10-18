// ============================================================================
// detectorSupport/orderByKey.js —— [D106] 参数名点「固定后缀」形态差分验证器
// ----------------------------------------------------------------------------
// 场景（P1-2）：后端把键名拼进 **ORDER BY 位置**且后面还有固定尾部语法：
//   `SELECT ... FROM t ORDER BY ${key} DESC`
// 该形态下既有通道全盲（真 MySQL 靶场实测零检出，请求 64）：
//   · 布尔通道 `{k} AND 1=1-- -` / `{k} AND 1=2-- -` 在 ORDER BY 里退化成
//     `ORDER BY price AND 1=1`（恒真=price）与 `ORDER BY price AND 1=2`（恒 0 常量）
//     ——常量排序并不改变可观察结果，真假无差分（与 TODO.md §M 同源的老坑）；
//   · union 通道在语法上不可表达：ORDER BY 是 UNION 之后才允许的末段，
//     `ORDER BY x UNION SELECT ...` 对任何 SQL 方言都是语法错误 ⇒ 扫不到也不能报。
//
// 判据（本验证器）：键名后追加**序数探针**——
//   P1 = `${orig}, 1-- -`    有效（裸整数按 select 列表序号解析：1 合法）
//   P2 = `${orig}, 9999-- -` 越界（MySQL/MariaDB/TiDB/PG：Unknown column '9999' in
//                            'order clause' / ORDER BY position 9999 is not in select list）
// P1 与 P2 的响应分化 ⇒ 键名确实落进了 SQL 的 ORDER BY 表达式树。
// 归类布尔差分族（technique='boolean'，报告/风险/统计零新增类型）。
//
// 诚实边界：
//   · 序数越界报错是 MySQL 系与 PG 的语义；MSSQL/SQLite/Oracle 把裸整数当常量 →
//     两探针都有效且结果同序 ⇒ 无差分 ⇒ 诚实假阴性；
//   · 目标把 SQL 错误吞成与正常页完全相同（无任何可观察差异）⇒ 假阴性；
//   · 键名拼接处若本身带括号/函数包裹（`ORDER BY SUBSTRING_INDEX(${k},...)`），
//     `, 9999` 可能同错 ⇒ 假阴性；
//   · 反射页会剥离回显的载荷增量再比较（_stripReflected），不靠回显自证。
// ============================================================================
import { Detector } from '../Detector.js';
import { createDetectionResult } from '../models.js';
import { applyProbeOutcome, probeOnce } from './probeOnce.js';

const COMMENT = '-- -';

/** 序数探针仅适用于非 XML 参数名点（值点/XML 元素名点零请求，不进本通道）。 */
function sortApplicable(point) {
  return point.location === 'paramName' && point.carrier !== 'xml' && !!String(point.originalValue || '');
}

export class OrderByKeyDetector extends Detector {
  constructor() {
    super('boolean'); // 归类布尔差分族（报告/风险/统计沿用既有通道，不新增技术类型）
  }

  /**
   * 与 BooleanBlindDetector/UnionDetector 同套容差（长度 12%+24B、字符差异率 15%）：
   * 常量排序页与越界错误页的长度可能接近，必须靠内容差异率区分，不能靠长度。
   */
  _similar(a, b) {
    if (a === b) return true;
    const la = a.length;
    const lb = b.length;
    if (Math.abs(la - lb) > Math.max(24, lb * 0.12)) return false;
    const m = Math.min(la, lb);
    let diffs = 0;
    for (let i = 0; i < m; i++) if (a[i] !== b[i]) diffs++;
    return diffs + Math.abs(la - lb) < Math.max(la, lb) * 0.15;
  }

  /**
   * 两轮探针：P1/P2 分化 → 复核轮各自稳定且仍分化才落槌。
   * @typedef {{ status: 'vuln', lengths: { valid: number, outOfRange: number } }
   *   | { status: 'none' }
   *   | { status: 'inconclusive', reason: string }} OrderByProbeOutcome
   * @param {(value: string) => Promise<any>} send
   * @param {string} orig 键名本身（point.originalValue）
   * @returns {Promise<OrderByProbeOutcome>}
   */
  async _probeOrdinal(send, orig) {
    const p1 = `${orig}, 1${COMMENT}`;
    const p2 = `${orig}, 9999${COMMENT}`;

    const a = await probeOnce(this, send, p1, 'ORDER BY 序数探针');
    if (!a.ok) return { status: 'inconclusive', reason: a.why };
    if (this._isWafBlockPage(a.res)) return { status: 'none' }; // 拦截页：参照不可信
    const b = await probeOnce(this, send, p2, 'ORDER BY 越界探针');
    if (!b.ok) return { status: 'inconclusive', reason: b.why };

    const n1 = this._stripReflected(a.body, p1, orig);
    const n2 = this._stripReflected(b.body, p2, orig);
    if (this._similar(n1, n2)) return { status: 'none' }; // 无分化 ⇒ 键名未进 SQL 表达式

    // 复核轮：两侧各自可复现且分化仍成立
    const a2 = await probeOnce(this, send, p1, '复核序数探针');
    if (!a2.ok) return { status: 'inconclusive', reason: a2.why };
    const b2 = await probeOnce(this, send, p2, '复核越界探针');
    if (!b2.ok) return { status: 'inconclusive', reason: b2.why };
    const n1b = this._stripReflected(a2.body, p1, orig);
    const n2b = this._stripReflected(b2.body, p2, orig);
    if (!this._similar(n1, n1b) || !this._similar(n2, n2b)) return { status: 'none' }; // 页面抖动 ⇒ 差分不可信
    if (this._similar(n1b, n2b)) return { status: 'none' };

    return { status: 'vuln', lengths: { valid: n1.length, outOfRange: n2.length } };
  }

  /**
   * @param {object} ctx { httpClient, target, point, dbms, config }
   * @returns {Promise<import('../models.js').DetectionResult>}
   */
  async detect(ctx) {
    const { target, point, dbms } = ctx;
    const result = createDetectionResult(point.id, 'boolean');
    // 前置边界（零请求）：只对**非 XML** 参数名点生效——XML 元素名承载不了 `, 1-- -`
    // （NameChar 不允许空格/逗号），XML 面由 xmlParamName.js 的位移探针负责。
    if (!sortApplicable(point)) return result;

    const orig = String(point.originalValue || '');
    const payloads = [`${orig}, 1${COMMENT}`, `${orig}, 9999${COMMENT}`];
    const send = (value) => this.send(ctx.httpClient, ctx, this.buildRequest(target, point, value));
    const out = await this._probeOrdinal(send, orig);
    if (!applyProbeOutcome(result, out, dbms)) return result;
    if (out.status !== 'vuln') return result; // 类型收窄（applyProbeOutcome 已保证）

    result.payloads = payloads;
    result.evidence =
      `ORDER BY 固定后缀形态：\`${orig}, 1-- -\` 响应正常（${out.lengths.valid}B）而 ` +
      `\`${orig}, 9999-- -\` 分化（${out.lengths.outOfRange}B，序数越界），复核轮两侧各自稳定 ` +
      `⇒ 键名被拼进 ORDER BY 表达式树（列名/序号解析域）。`;
    result.trace = { kind: 'paramname-ordery-diff', key: orig, lengths: out.lengths };
    return result;
  }
}

export const orderByKeyDetector = new OrderByKeyDetector();
export default OrderByKeyDetector;
