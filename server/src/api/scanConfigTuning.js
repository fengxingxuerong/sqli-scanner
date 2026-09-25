// ============================================================================
// scanConfigTuning.js —— 「提取 / 统计层面」可调旋钮的入口收敛
//
// [2026-09-24] 从 api/scanRoutes.js 的 sanitizeStart 抽出，两个理由：
//   1. 这批键（11 个）是同一形状：单值严格透传 + 一个嵌套阈值组带底，留在 sanitizeStart
//      里只会把那文件继续往 1200 行预算外推（arch:guard 的量级门禁不是装饰）；
//   2. 抽出来后它是一条**可单独穷举**的闸门：新增一个这类旋钮时，改这个文件 +
//      defaults.js + KNOWN_CFG_KEYS 三处，守卫 tests/configWhitelist.passthrough.test.js
//      会逐键真调 sanitizeStart 验落地。
//
// 依赖方向：本模块是叶子（只依赖 defaults / scanValidityGuard 的常量 / scanConfigUtils
// 的纯函数），不反向依赖 scanRoutes。
//
// 职责边界：只做「用户发来的调优键 → 合法值写入 config」；不做键名白名单判定
// （那是 KNOWN_CFG_KEYS 的事）、不做跨字段校验。
// ============================================================================
import { defaults } from '../config/defaults.js';
import { logger } from '../core/logger.js';
import { VALIDITY_DEFAULTS } from '../core/scanValidityGuard.js';
import { clampNum, diffDroppedConfigKeys, pickBool, pickInt } from './scanConfigUtils.js';

/**
 * 把提取/统计层的调优键收敛进 config（就地写入）。
 * 每个键的**默认值逐个等于引擎内部兜底值** ⇒ 不发等于零行为变化；本批补的是"能发"。
 * @param {object} config sanitizeStart 正在构建的配置对象
 * @param {object} cfg 请求体里的原始 config
 */
/**
 * 「静默丢弃必须喊出来」的播报壳。判据本身是纯函数 `scanConfigUtils.diffDroppedConfigKeys`
 * （可单测、不 IO），这里只负责把它翻成两条 warn —— 与本文件其它 knob 同一形状：
 * 键名在白名单内但值没落地，后果与未知键完全相同（200 + scanId + 报告一句「未检出」）。
 *
 * ⚠ 调用时机必须在**所有**写 config 的步骤之后（含 BACKFILL_SCALAR_KEYS 兜底透传）。
 * 实测过的反向缺陷：放在兜底之前，18 个"靠兜底才落地"的键全被判成"被丢弃…设置不会生效"，
 * 而它们其实都在返回的 config 里 —— 假告警和静默丢弃是同级的错，会把人支使去改一个
 * 本来正确的配置。不变式由 server/tests/configDroppedKeys.warn.test.js 遍历兜底名单钉住。
 */
export function warnDroppedConfigKeys(cfg, knownKeys, config, directOnlyKeys) {
  const dropped = diffDroppedConfigKeys(cfg, knownKeys, config, directOnlyKeys);
  if (dropped.unknown.length) {
    logger.warn(
      `扫描配置含 ${dropped.unknown.length} 个未知字段，已忽略（这些设置**不会生效**，请核对键名或改用 CLI）：${dropped.unknown.join(', ')}`
    );
  }
  if (dropped.shapeDropped.length) {
    logger.warn(
      `扫描配置有 ${dropped.shapeDropped.length} 个键被丢弃（键名在白名单内，但**值形态不合该键的校验**，` +
        '设置不会生效；部分键需与父键同发，如 safeFreq 需 safeUrl、csrfTokenName 需 csrfUrl）：' +
        dropped.shapeDropped.map((k) => `${k}=${JSON.stringify(cfg[k])}`).join(', ')
    );
  }
}

export function applyTuningKnobs(config, cfg) {
  // ── 严格布尔：hex / flushSession ────────────────────────────────────────
  // [2026-09-24] 从 sanitizeStart 原样搬来（含告警文案），与本模块其余键同一形状。
  // 通用标量透传会把 1 / "true" / {} 这类 truthy 值原样收下，而引擎按 `config.hex === true`
  // 判定（Extractor.js:618,697）—— 结果就是"API 收了、引擎不生效"，与本仓反复清理的
  // 「白名单有、透传没有」是同一个 bug 形状，只是换了触发条件。宁可拒掉并说明。
  for (const boolKey of ['hex', 'flushSession']) {
    if (!(boolKey in cfg)) continue;
    const v = cfg[boolKey];
    if (typeof v === 'boolean') config[boolKey] = v;
    else logger.warn(`${boolKey} 需为布尔值（收到 ${JSON.stringify(v)}），已丢弃——该开关按严格 true 判定，传 truthy 非布尔值不会生效`);
  }

  // ── 严格布尔位（引擎判据分别是 `=== true` / `!== false` / `!== true`，三种都要求键存在
  //    才是用户真正表达的意图，故逐个显式转发；非法/未传则留给 defaults 浅合并）──
  // 位平面提取（每字符 1 轮请求，仅 MySQL/MariaDB/TiDB 族；失败整体回落二分）
  const blindBitwise = pickBool(cfg, 'blindBitwise');
  if (blindBitwise !== undefined) config.blindBitwise = blindBitwise;
  // 布尔通道的「空基线」OR 型兜底对：关掉省 2 请求/点，代价是少一条漏报防线
  const booleanOrFallback = pickBool(cfg, 'booleanOrFallback');
  if (booleanOrFallback !== undefined) config.booleanOrFallback = booleanOrFallback;
  // union 反射门控逃生口（true=跳过门控）。门控本身是误报防线，默认不跳。
  const unionSkipGate = pickBool(cfg, 'unionSkipGate');
  if (unionSkipGate !== undefined) config.unionSkipGate = unionSkipGate;

  // ── 数值位 ──────────────────────────────────────────────────────────────
  // 盲注单字段长度上界。引擎判据是 `Number(x) > 255` 才采纳，否则回落 4096 ——
  // 与其让它静默回落，不如在入口就把合法域（256~65535）钉住。
  const blindMaxLen = pickInt(cfg, 'blindMaxLen', defaults.blindMaxLen, 256, 65535);
  if (blindMaxLen !== undefined) config.blindMaxLen = blindMaxLen;
  // deepDump 分页聚合每页行数（规避 LISTAGG 4000 / GROUP_CONCAT 1024 截断）
  const deepDumpPageSize = pickInt(cfg, 'deepDumpPageSize', defaults.deepDumpPageSize, 1, 2000);
  if (deepDumpPageSize !== undefined) config.deepDumpPageSize = deepDumpPageSize;
  // 拖库断点写入会话的行间隔（只影响续跑省多少请求，不影响结果正确性）
  const dumpCheckpointInterval = pickInt(cfg, 'dumpCheckpointInterval', defaults.dumpCheckpointInterval, 1, 100000);
  if (dumpCheckpointInterval !== undefined) config.dumpCheckpointInterval = dumpCheckpointInterval;
  // 时间定库的 sleep 与阈值：与时间盲注**刻意分开**——定库要快（每库一条向量），
  // 复用 timeBlindSleepSec 会把 18 库遍历的墙钟放大到不可接受。
  const fingerprintSleepSec = pickInt(cfg, 'fingerprintSleepSec', defaults.fingerprintSleepSec, 1, 30);
  if (fingerprintSleepSec !== undefined) config.fingerprintSleepSec = fingerprintSleepSec;
  const fingerprintTimeThresholdMs = pickInt(cfg, 'fingerprintTimeThresholdMs', defaults.fingerprintTimeThresholdMs, 100, 60000);
  if (fingerprintTimeThresholdMs !== undefined) config.fingerprintTimeThresholdMs = fingerprintTimeThresholdMs;
  // 预筛选时间预算：prefilter.js 的判据是 `Number.isFinite(x) && x > 0`，
  // 非有限值它自己会回落到"实测基线 RTT 自适应"；这里只保证进来的是合法预算。
  const prefilterBudgetMs = pickInt(cfg, 'prefilterBudgetMs', 1500, 100, 300000);
  if (prefilterBudgetMs !== undefined) config.prefilterBudgetMs = prefilterBudgetMs;
  // 提取阶段响应上限：**不写默认值**是刻意的 —— 引擎侧是
  // `config.maxExtractBodyBytes ?? EXTRACT_MAX_BODY_BYTES`，而后者由 env
  // EXTRACT_MAX_BODY_MB 推导；在这里塞 defaults 会让那条 env 永久失效。
  const maxExtractBodyBytes = pickInt(cfg, 'maxExtractBodyBytes', undefined, 1024 * 1024, 1024 * 1024 * 1024);
  if (maxExtractBodyBytes !== undefined) config.maxExtractBodyBytes = maxExtractBodyBytes;

  // ── 结论可信度守卫阈值组（必须带底重建）──────────────────────────────────
  // 浅合并下少转发一个子键，引擎侧就是 undefined 而不是 VALIDITY_DEFAULTS 的值，
  // 而 windowSize / minSamples 这类阈值"缺席"不是"用默认"，而是**参与判定的分母**。
  // （同日教训：blindRobust.extractVerify 因判据写成 `!== false` 躲过了"键存在吗"式检查。）
  // 唯一真相在 scanValidityGuard 那份常量里 —— import 过来，而不是在 defaults.js 抄一份数字。
  if (cfg.scanValidity && typeof cfg.scanValidity === 'object' && !Array.isArray(cfg.scanValidity)) {
    const sv = cfg.scanValidity;
    // `enabled` 不在 VALIDITY_DEFAULTS 里（那份常量只有阈值），但带底必须写上：
    // scanRunner.js 的判据是 `validityCfg.enabled !== false`，现场要能区分
    // "用户没配"与"键不存在"。
    const out = { enabled: true, ...VALIDITY_DEFAULTS };
    const en = pickBool(sv, 'enabled');
    if (en !== undefined) out.enabled = en;
    for (const k of ['windowSize', 'blockMinHits', 'authStreak', 'minSamples', 'abortAfterFails']) {
      const v = pickInt(sv, k, VALIDITY_DEFAULTS[k], 1, 100000);
      if (v !== undefined) out[k] = v;
    }
    for (const k of ['blockRatio', 'serverErrRatio']) {
      const raw = sv[k];
      // 不新增 pickNum：scanConfigUtils 的语义是「未传 → undefined（该键不写入）」，
      // 这层判断留在调用点，公共 API 面不再长。
      const v = raw === undefined || raw === null ? undefined : clampNum(raw, VALIDITY_DEFAULTS[k], 0.01, 1);
      if (v !== undefined) out[k] = v;
    }
    config.scanValidity = out;
  }
}
