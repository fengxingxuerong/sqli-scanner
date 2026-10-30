// ============================================================================
// detectorSupport/keyBool.js —— 多键拼接形态的「键名注入」验证器
// ----------------------------------------------------------------------------
// [D169 2026-10-26 立，D173 扩到 query 载体]
// 场景：后端把**全部字段名/参数名**拼成 WHERE 条件（`WHERE k1 = 'v1' AND k2 = 'v2'`，
// 值做过转义/参数化）。键名落在**布尔表达式位置**——和 D166 的 ORDER BY 位置不同：
//   · orderByKey 的序数差分（`{k}, 1-- -` vs `{k}, 9999-- -`）在这里只会语法错误；
//   · 通用布尔通道的载荷是 `{k} AND 1=1-- -`，而 `{k}` 是 varchar 列名 ⇒ MySQL 把它当
//     数值 0 ⇒ 恒真/恒假两页都是「0 行」⇒ 无分化（实测 /api/form-filter-blind 0 检出）。
// 判据：把整个键名换成一个**自洽的布尔表达式**，并用行注释吞掉后面的固定后缀：
//   T = `{k} = 'x' OR 1=1-- `   → WHERE 恒真 → 全部行
//   F = `{k} = 'x' OR 1=2-- `   → 0 行
//   C = `<随机未知列> = 'x' OR 1=1-- ` → 未知列报错（盲档吞成 0 行）
// T/F 分化且两轮各自稳定、C 不≈T ⇒ 键名确实进了 SQL 表达式。
//
// 载体（carrier）：`form`（multipart 表单字段名，D169）与 `query`（URL query 键名，D173）。
// 二者构造侧都只改**键名**、值原样保留（buildFormNameRequest / buildParamNameRequest），
// 所以同一套判据直接复用；JSON 键名暂不接（键的引号/转义语义不同，未验）。
//
// 为什么用 `-- `（带尾空格）而不是 `/* */` 或 `-- -`：
//   · `/* */` 是**闭合**注释，吞不掉键名后面那段固定后缀（` = '值' AND ...`）——
//     实测恒真/恒假两页会**反转**（`1=1 = 'alice'` 求值为假），判据直接失效；
//   · `-- -` 在 Derby 上 Lexical error（D167 实测）；
//   · `-- ` 是四种引擎共同认的形态：MySQL 要求 `--` 后跟空白，Derby/H2/HSQLDB 都接受。
//   真库验证（MariaDB）：`name = 'x' OR 1=1-- ` 返回全部行、`OR 1=2-- ` 返回空、
//   未知列对照返回空。
// ============================================================================
import { Detector } from '../Detector.js';
import { createDetectionResult } from '../models.js';
import { chunkedSimilar } from './similarity.js';

const COMMENT = '-- ';

/** 本判据适用的载体（键名注入面）：form 字段名 / query 参数名 / JSON body 键名 */
const KEY_CARRIERS = new Set(['form', 'query', 'json']);

/** 随机后缀（未知列对照用；避免与真实列名撞车） */
const rndTag = () => Math.random().toString(36).slice(2, 8);

export class KeyBoolDetector extends Detector {
  constructor() {
    super('boolean'); // 归属布尔差分族（报告/风险/统计沿用既有通道）
  }

  /**
   * @param {object} ctx { httpClient, target, point, dbms, config }
   * @returns {Promise<import('../models.js').DetectionResult>}
   */
  async detect(ctx) {
    const { target, point } = ctx;
    const result = createDetectionResult(point.id, 'boolean');
    // 只对「键名注入面」生效：form 字段名 / query 参数名 / JSON body 键名。
    // XML 元素名受 NameChar 约束，本判据的载荷形态在元素名位置上不合法（D105 单独覆盖）。
    if (!point || !KEY_CARRIERS.has(point.carrier)) return result;
    const key = String(point.originalValue || '');
    if (!key) return result;

    const send = (value) => this.send(ctx.httpClient, ctx, this.buildRequest(target, point, value));
    const payloads = await this._probeForKey(send, key);
    if (!payloads) return result;

    result.vulnerable = true;
    result.payloads = payloads;
    const carrierZh = point.carrier === 'query' ? '查询参数名'
      : point.carrier === 'json' ? 'JSON 键名' : '表单字段名';
    result.evidence =
      `多键拼接（${carrierZh}进 WHERE 布尔位置）：`
      + '`{名} = \'x\' OR 1=1-- ` 返回全部行，`OR 1=2-- ` 为空，未知列对照不分化，'
      + '复核轮两侧各自稳定 ⇒ 键名被拼进 SQL 表达式。';
    result.trace = { kind: 'key-bool', carrier: point.carrier, key };
    return result;
  }

  /**
   * [D174 拆分] 三值对照 + 复核轮：恒真/恒假分化、未知列对照不分化、两侧各自可复现。
   *
   * 拆出来的原因：`detect` 加第 3 个载体后圈复杂度 17（软上限 15），按仓库纪律拆函数
   * 而不是抬基线。语义与原内联版逐条一致。
   * @param {(v: string) => Promise<any>} send 探针发送器（已绑定 target/point）
   * @param {string} key 原键名
   * @returns {Promise<string[]|null>} 判为注入时返回两条载荷，否则 null
   */
  async _probeForKey(send, key) {
    const payloadT = `${key} = 'x' OR 1=1${COMMENT}`;
    const payloadF = `${key} = 'x' OR 1=2${COMMENT}`;
    const payloadC = `sqli_nope_${rndTag()} = 'x' OR 1=1${COMMENT}`;

    const t = await this._bodyOf(send, payloadT, key);
    const f = await this._bodyOf(send, payloadF, key);
    if (t == null || f == null || chunkedSimilar(t, f)) return null;
    // 负向对照：未知列也≈恒真页 ⇒ 键名根本没进 SQL（或错误被渲染成正常页），不可信
    const c = await this._bodyOf(send, payloadC, key);
    if (c != null && chunkedSimilar(c, t)) return null;
    // 复核轮：两侧各自可复现且分化仍成立
    const t2 = await this._bodyOf(send, payloadT, key);
    const f2 = await this._bodyOf(send, payloadF, key);
    if (t2 == null || f2 == null) return null;
    if (!chunkedSimilar(t, t2) || !chunkedSimilar(f, f2) || chunkedSimilar(t2, f2)) return null;
    return [payloadT, payloadF];
  }

  /**
   * 发一条探针并返回「剔除回显后」的正文；不可用响应返回 null。
   * @param {(v: string) => Promise<any>} send
   * @param {string} payload 本次注入值（字段名）
   * @param {string} orig 原字段名（_stripReflected 的第二个基准）
   * @returns {Promise<string|null>}
   */
  async _bodyOf(send, payload, orig) {
    try {
      const res = await send(payload);
      if (!res || this.unusableOf(res)) return null;
      return this._stripReflected(String(res.data ?? ''), payload, orig);
    } catch {
      return null;
    }
  }
}

export const keyBoolDetector = new KeyBoolDetector();
export default KeyBoolDetector;
