// ============================================================================
// detectorSupport/callProcName.js —— `{call <名>}` / CALL 语句「过程名·表达式位」验证器
// ----------------------------------------------------------------------------
// [D284 2026-11-11 立] 补上 D116 单列的能力缺口：后端把参数名/字段名直接拼进 JDBC
// call escape —— `String sql = "{call " + param + "}"; connection.prepareCall(sql)`。
// 注入点不是「值位」而是**过程名/表达式位**：值位载荷（`' AND 1=1-- ` 等）在名字位
// 只会语法错误、与基线错误同形，四条标准通道全盲（D116 实测 4 真值 0 检出）。
//
// 关键事实（HSQLDB 2.x）：`{call X}` 交给 CALL 语句，而 CALL 接受**任意值表达式**——
// 名字位实际是表达式位。真机取证（2026-11-10，BenchmarkTest00590/01460，HSQLDB 2.7.4）：
//   · 基线 `{call BenchmarkTest00590}` → 500 `SQLSyntaxErrorException: object not found`
//   · `{call 1/0}`                     → 500 `java.sql.SQLDataException: division by zero`
//   · `{call CONCAT(CHAR(90),CHAR(81))}` → 200 成功页回显求值结果「ZQ」
//
// 判据（双通道，任一独立成立即命中；对照探针 + 两轮复跑沿 keyBool 同款纪律）：
//   echo：随机标记的求值结果在两轮响应中都出现。
//         标记取 6 位 [a-z0-9]（36^6 ≈ 2.2e9，页文巧合概率 ~1e-5 量级——两位大写会撞上
//         SQL/HTML 这类正文序列，实测口径不可用），载荷关键词全大写 ⇒ 目标把参数名原样
//         回显也造不出小写数字标记，反射/巧合双排除是构造性的。
//         HSQLDB 的 CONCAT 只收两参 ⇒ 嵌套 CONCAT（MySQL/SQLServer/PG 均兼容）。
//   eval-err：`1/0` 的求值类错误签名（division by zero 族）出现，而未知标识符对照
//         不出现——固定错误页（所有 SQL 错误渲染同一页）由「签名也出现在对照页 ⇒ 压制」
//         覆盖；刻意不做页面相似度比较（模板化错误页 95% 同构，会把真阳性一起压死）。
//
// 载体：query / json / form 键名（与 keyBool 同口径；XML 元素名受 NameChar 约束，
// 括号/逗号不合法，本判据不接）。挂在参数名点零命中后链的第三步
// （orderByKey → keyBool → 本验证器），不重复探测已命中的点。
//
// 诚实边界：
//   · 盲档（错误被吞成正常页 + 无求值回显通道）不可见——此时 CALL 位本身无观察面；
//   · 非表达式型 CALL 位（严格只认存储过程名的引擎/驱动）两通道都不成立，不误报；
//   · Oracle/PG 无 CHAR(n) 数值→字符语义（PG 会当类型转换），ctx.dbms 已知时换 CHR() 变体。
// ============================================================================
import { Detector } from '../Detector.js';
import { createDetectionResult } from '../models.js';

/** 本判据适用的载体（键名注入面）：form 字段名 / query 参数名 / JSON body 键名 */
const CALL_KEY_CARRIERS = new Set(['form', 'query', 'json']);

/**
 * 求值类错误签名（1/0 的除零族）。覆盖实测四种引擎的文案形态：
 * HSQLDB「data exception: division by zero」、PG「division by zero」、
 * MySQL「Division by 0」、SQLServer「Divide by zero error」、Oracle「ORA-01476」。
 * 故意不收宽泛的「data exception / error」——那会撞上基线自身的报错文案。
 * @type {RegExp}
 */
const EVAL_ERR_RE = /div(?:ision|ide) by (?:zero|0)|ORA-01476/i;

/** 随机标记字符池：小写字母 + 数字（36 字符；载荷关键词 CONCAT/CHAR 全大写 ⇒ 反射造不出标记） */
const MARKER_POOL = 'abcdefghijklmnopqrstuvwxyz0123456789';

const rndTag = () => Math.random().toString(36).slice(2, 8);

/** 随机 6 位标记（期望的求值结果） */
function randomMarker() {
  let text = '';
  for (let i = 0; i < 6; i += 1) text += MARKER_POOL[Math.floor(Math.random() * MARKER_POOL.length)];
  return text;
}

/**
 * 求值回显载荷：`CONCAT(...CONCAT(CHAR(c1),CHAR(c2))...,CHAR(c6))` 嵌套形态
 * （HSQLDB CONCAT 只收两参）。fn=CHR 时同构换函数名（PG/Oracle）。
 * @param {string} fn 'CHAR' | 'CHR'
 * @param {string} marker 6 位标记
 */
function echoPayloadFor(fn, marker) {
  const codes = [...marker].map((c) => c.charCodeAt(0));
  // 右结合链：CONCAT(CHAR(c1),CONCAT(CHAR(c2),…CHAR(c6)))——两参 CONCAT 的正确嵌套
  let expr = `${fn}(${codes[codes.length - 1]})`;
  for (let i = codes.length - 2; i >= 0; i -= 1) expr = `CONCAT(${fn}(${codes[i]}),${expr})`;
  return expr;
}

/**
 * 按方言选「整数→字符」函数名：PG/Oracle/DM8（达梦归 Oracle 族，见 dialects.json 映射）
 * 是 CHR，其余（HSQLDB/MySQL/SQLServer/H2 等）是 CHAR。dbms 传入的是指纹显示名
 * （'PostgreSQL'/'Oracle'/'DM8'），统一归一化小写再判。
 * 无 CONCAT 的方言（Derby 用 ||）echo 通道自然闭合计为不命中，error 通道不受影响。
 * @param {string|null} dbms 指纹方言名
 */
function charFnFor(dbms) {
  const d = String(dbms || '').toLowerCase();
  return d === 'postgresql' || d === 'postgres' || d === 'oracle' || d === 'dm8' || d === 'dameng'
    ? 'CHR'
    : 'CHAR';
}

export class CallProcNameDetector extends Detector {
  constructor() {
    // 归属报错/求值回显族（报告/风险/统计沿用既有 error 通道）；判定算子含 echo 与 signature 两类
    super('error', { match: ['echo', 'signature'], extract: [] });
  }

  /**
   * @param {object} ctx { httpClient, target, point, dbms, config }
   * @returns {Promise<import('../models.js').DetectionResult>}
   */
  async detect(ctx) {
    const { target, point } = ctx;
    const result = createDetectionResult(point.id, 'error');
    if (!point || point.location !== 'paramName') return result;
    if (!CALL_KEY_CARRIERS.has(point.carrier)) return result;
    const key = String(point.originalValue || '');
    if (!key) return result;

    const send = (value) => this.send(ctx.httpClient, ctx, this.buildRequest(target, point, value));
    const hit = await this._probeForCall(send, ctx.dbms);
    if (!hit) return result;

    result.vulnerable = true;
    result.payloads = hit.payloads;
    result.evidence = hit.evidence;
    result.trace = { kind: 'call-proc-name', carrier: point.carrier, key, channel: hit.channel };
    return result;
  }

  /**
   * [D284] 双通道探针 + 对照 + 复跑。请求预算固定 4 条（echo/err/ctrl/echo 复跑），
   * 只在参数名点零命中后链到达时执行（不重复探测已命中的点）。
   * @param {(v: string) => Promise<any>} send 探针发送器（已绑定 target/point）
   * @param {string|null} dbms 指纹出的方言（选 CHAR/CHR 变体）
   * @returns {Promise<{payloads: string[], evidence: string, channel: string}|null>}
   */
  async _probeForCall(send, dbms) {
    const fn = charFnFor(dbms);
    const marker = randomMarker();
    const echoPayload = echoPayloadFor(fn, marker);
    const errPayload = '1/0';
    const ctrlPayload = `sqli_nope_${rndTag()}`;

    const e1 = await this._bodyOf(send, echoPayload);
    const e2 = await this._bodyOf(send, echoPayload);
    if (e1 == null || e2 == null) return null;
    // echo 通道：标记两轮都在、对照页没有（构造性反射安全：载荷关键词全大写，反射造不出小写数字标记）
    if (e1.includes(marker) && e2.includes(marker)) {
      const ctrl = await this._bodyOf(send, ctrlPayload);
      if (ctrl == null || !ctrl.includes(marker)) {
        return {
          payloads: [echoPayload],
          channel: 'echo',
          evidence:
            `{call <名>} / CALL 表达式位（键名进过程名位）：\`${echoPayload}\` 求值结果「${marker}」` +
            '在两轮响应中稳定回显，未知标识符对照无此回显 ⇒ 名字被拼进 CALL 位并被数据库求值。',
        };
      }
    }
    // eval-err 通道：1/0 的除零签名出现、对照不出现。固定错误页（所有 SQL 错误渲染同一页）
    // 由「签名也出现在对照页 ⇒ 压制」覆盖——**不做**页面相似度比较：真错误页 95% 是同一套
    // 模板（异常只在消息行不同），相似度守卫会把模板化回显的真阳性一起压死。
    const err = await this._bodyOf(send, errPayload);
    const ctrl = await this._bodyOf(send, ctrlPayload);
    if (err == null || ctrl == null) return null;
    if (EVAL_ERR_RE.test(err) && !EVAL_ERR_RE.test(ctrl)) {
      return {
        payloads: [errPayload, ctrlPayload],
        channel: 'eval-err',
        evidence:
          '{call <名>} / CALL 表达式位（键名进过程名位）：`1/0` 产生求值类错误（division by zero 族），' +
          '未知标识符对照无此签名（非固定错误页）⇒ 名字被拼进 CALL 位并被数据库求值。',
      };
    }
    return null;
  }

  /**
   * 发一条探针并返回「剔除回显后」的正文；不可用响应返回 null（与 keyBool 同口径）。
   * @param {(v: string) => Promise<any>} send
   * @param {string} payload 本次注入值（键名位载荷）
   * @returns {Promise<string|null>}
   */
  async _bodyOf(send, payload) {
    try {
      const res = await send(payload);
      if (!res || this.unusableOf(res)) return null;
      return this._stripReflected(String(res.data ?? ''), payload);
    } catch {
      return null;
    }
  }
}

export const callProcNameDetector = new CallProcNameDetector();
export default CallProcNameDetector;
