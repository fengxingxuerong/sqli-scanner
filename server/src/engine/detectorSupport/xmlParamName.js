// ============================================================================
// detectorSupport/xmlParamName.js —— [D105 2026-10-18] XML 元素名参数名注入的专用验证器
// ----------------------------------------------------------------------------
// 为什么不是普通检测器赛道的载荷：通用布尔/UNION/报错载荷都含空格/引号/括号，
// XML NameChar 不允许这些字符 ⇒ 载荷进了元素名就是畸形报文（目标解析失败，整轮判「不可注入」）。
// 能塞进元素名的 SQL 语义只剩「列名 + 算术位移」：
//   基线  B  = `WHERE ${tag} = ?`
//   恒等  P0 = `WHERE ${tag}-0 = ?`   （数值/十进制列上与原式同真值）
//   位移  P1 = `WHERE ${tag}-1 = ?`   （真值恰偏移 1 ⇒ 行集应不同）
// 判定（sound，宁漏不误）：
//   P0 响应 === B 响应  ∧  P1 响应 !== B 响应
// ⇒ 元素名确实进了 SQL 表达式（白名单/字面量/未知列错误三种安全形态都会先破坏第一条：
//   拒绝/回退的键要么与基线不同，要么 P0/P1 同错页）。
// 复核轮（防单次抖动/动态页）：B 与 P1 各重发一次，要求 B 自稳且 P1 仍异于 B。
//
// 诚实边界（写进证据与文档，不装作覆盖）：
//   · 仅数值语境列：字符串列上 `tag-0` 触发隐式数值转换，恒等不成立 ⇒ 判不出（假阴性）；
//   · 仅 `WHERE ${tag} = ?` 形态；ORDER BY / 表名等位置不在本探针族（无固定值参照）；
//   · 页面须可复现（含时间戳等动态块的页面 B 不自稳 ⇒ 判不出）；错误差分通道另批评估。
// ============================================================================
import { Detector } from '../Detector.js';
import { createDetectionResult } from '../models.js';
import { applyProbeOutcome, probeOnce } from './probeOnce.js';
import { isXmlName } from '../../core/xmlBody.js';

export class XmlParamNameDetector extends Detector {
  constructor() {
    super('boolean'); // 归类布尔差分族（报告/风险/统计沿用既有通道，不新增技术类型）
  }

  /**
   * 四段判定（基线→恒等→位移→复核）。单独成方法只为把分支与「结果组装」分开
   * （复杂度门禁；语义不变）。
   * @typedef {{ status: 'vuln', lengths: { baseline: number, shift0: number, shift1: number } }
   *   | { status: 'none' }
   *   | { status: 'inconclusive', reason: string }} ShiftProbeOutcome
   * @param {(name: string) => Promise<any>} send
   * @param {string} tag
   * @returns {Promise<ShiftProbeOutcome>}
   */
  async _probeShift(send, tag) {
    const b = await probeOnce(this, send, tag, 'XML 元素名探针基线');
    if (!b.ok) return { status: 'inconclusive', reason: b.why };
    const bodyB = b.body;
    if (this._isWafBlockPage(b.res)) return { status: 'none' }; // 基线即拦截页：参照不可信

    const p0 = await probeOnce(this, send, `${tag}-0`, '恒等位移探针');
    if (!p0.ok) return { status: 'inconclusive', reason: p0.why };
    if (p0.body !== bodyB) return { status: 'none' }; // 恒等不成立 ⇒ 名字未进 SQL 表达式

    const p1 = await probeOnce(this, send, `${tag}-1`, '单位位移探针');
    if (!p1.ok) return { status: 'inconclusive', reason: p1.why };
    if (p1.body === bodyB) return { status: 'none' }; // 位移未改变真值 ⇒ 非注入

    // 复核轮：B 自稳 + P1 仍异（两组各自独立成立才落槌）
    const b2 = await probeOnce(this, send, tag, '复核基线');
    if (!b2.ok) return { status: 'inconclusive', reason: b2.why };
    if (b2.body !== bodyB) return { status: 'none' }; // 页面不可复现 ⇒ 差分不可信
    const p1b = await probeOnce(this, send, `${tag}-1`, '复核位移探针');
    if (!p1b.ok) return { status: 'inconclusive', reason: p1b.why };
    if (p1b.body === bodyB) return { status: 'none' };
    return {
      status: 'vuln',
      lengths: { baseline: bodyB.length, shift0: p0.body.length, shift1: p1.body.length },
    };
  }

  /**
   * @param {object} ctx { httpClient, target, point, dbms, config }
   * @returns {Promise<import('../models.js').DetectionResult>}
   */
  async detect(ctx) {
    const { target, point, dbms } = ctx;
    const result = createDetectionResult(point.id, 'boolean');
    const tag = String(point.originalValue || '');
    // 前置边界（零请求）：非 NameChar 合法名或树缺失 ⇒ 本探针无法表达，判非注入（不猜）
    if (!isXmlName(tag) || !target || !target.xmlTree) return result;

    const send = (name) => this.send(ctx.httpClient, ctx, this.buildRequest(target, point, name));
    const out = await this._probeShift(send, tag);
    if (!applyProbeOutcome(result, out, dbms)) return result;
    if (out.status !== 'vuln') return result; // 类型收窄（applyProbeOutcome 已保证）

    result.payloads = [`${tag}-0`, `${tag}-1`];
    result.evidence =
      `XML 元素名算术位移差分：${tag}-0 响应与基线一致（${out.lengths.baseline}B），` +
      `${tag}-1 响应不同（${out.lengths.shift1}B），复核轮 B 自稳且 P1 仍异 ⇒ 元素名被拼进 SQL 表达式。` +
      `载体=XML body 元素名（NameChar 合法名，仅数值语境列可判）。`;
    result.trace = { kind: 'xml-paramname-shift', tag, lengths: out.lengths };
    return result;
  }
}

export const xmlParamNameDetector = new XmlParamNameDetector();

export default xmlParamNameDetector;
