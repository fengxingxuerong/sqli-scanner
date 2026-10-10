// ============================================================================
// paramSelection.js —— 注入点筛选三件套（[D41 2026-10-11 对标 sqlmap]）
//
//   -p / --test-param <p1,p2>   只测指定参数（参数名精确匹配，大小写不敏感）
//   --param-exclude <regex>     排除匹配的参数（正则，大小写不敏感）
//   --param-filter <place,...>  按位置筛选（url/body/header/cookie/path）
//
// 为什么单独一个模块：CLI（config.js）与 REST（scanGuard）都要把用户输入归一化成
// 同一种规范形态 —— 归一化写两份必然漂移（本仓教训：白名单语义漂移整批返工）。
// TargetParser 在注入点发现完成后调用 applyParamSelection 统一收口；
// scanGuard 只用前两个 normalize 函数做「形态收紧」，不越权做点位判定。
//
// 语义红线（与本仓 unknownFlag 硬拒同一条政策）：
//   筛选条件把点位删光 ≠ 「没有漏洞」，而是「用户没测」—— 必须显式报错并列出可用点位，
//   绝不允许静默跑成一场 0 点扫描然后报告「未检出」。
// ============================================================================
import { ErrorCode, AppError } from '../core/errors.js';

// 位置别名 → 规范 location 名（TargetParser 的 createInjectionPoint 第一参）。
// 兼容 sqlmap 风格写法（GET/POST/URI）与本仓规范名（url/body/header/cookie/path）。
const PLACE_ALIASES = {
  url: 'url',
  query: 'url',
  uri: 'url',
  get: 'url',
  body: 'body',
  post: 'body',
  form: 'body',
  header: 'header',
  headers: 'header',
  cookie: 'cookie',
  cookies: 'cookie',
  path: 'path',
};

/** 位置白名单展示串（报错文案用） */
export const PARAM_FILTER_PLACES = Object.keys(PLACE_ALIASES).join('/');

/**
 * --param-filter 值归一化：逗号串或数组 → 规范 location 数组。
 * 返回 null 表示未配置（零行为变化）。含未知位置时抛 INVALID_PARAM（宁可拒绝也不静默忽略）。
 * @param {string|string[]|undefined} raw
 * @returns {string[]|null}
 */
export function normalizeParamFilter(raw) {
  if (raw == null || raw === '') return null;
  const parts = (Array.isArray(raw) ? raw : String(raw).split(','))
    .map((s) => String(s).trim().toLowerCase())
    .filter(Boolean);
  if (!parts.length) return null;
  const out = [];
  for (const p of parts.slice(0, 8)) {
    const mapped = PLACE_ALIASES[p];
    if (!mapped) {
      throw new AppError(
        ErrorCode.INVALID_PARAM,
        `--param-filter 含未知位置「${p}」（支持：${PARAM_FILTER_PLACES}）`
      );
    }
    if (!out.includes(mapped)) out.push(mapped);
  }
  return out;
}

/**
 * --test-param 值归一化：逗号串或数组 → 参数名数组（保留原样大小写；匹配时大小写不敏感）。
 * 返回 null 表示未配置。
 * @param {string|string[]|undefined} raw
 * @returns {string[]|null}
 */
export function normalizeTestParameter(raw) {
  if (raw == null || raw === '') return null;
  const out = (Array.isArray(raw) ? raw : String(raw).split(','))
    .map((s) => String(s).trim())
    .filter(Boolean)
    .slice(0, 32);
  return out.length ? out : null;
}

/**
 * 注入点筛选统一收口（TargetParser.discover 尾部调用，* 精确标记之后、onlyPoint 之前）。
 *
 * 应用顺序（后条在前条结果上继续收窄）：
 *   ① paramFilter（按位置收窄）② testParameter（按参数名白名单）③ paramExclude（按参数名黑名单）。
 * 任何一步把点位删光 → 抛 INVALID_PARAM 并列出当前可用点位（红线：0 点扫描必须显式拒绝）。
 *
 * @param {Array<{location: string, param: string}>} points
 * @param {object|undefined} config
 * @returns {Array} 筛选后的点位（未配置任何筛选时原数组返回，零行为变化）
 */
export function applyParamSelection(points, config) {
  const cfg = config || {};
  // 入口归一化：CLI/REST/配置档案三路进来的形态不同（逗号串 / 数组 / 已归一数组），
  // 全部在这里收敛成规范形态 —— TargetParser 是唯一收口，不允许任何一侧自带私货口径。
  // 归一化本身可能抛 INVALID_PARAM（未知位置 / 非法正则），即硬拒语义的一部分。
  const paramFilter = normalizeParamFilter(cfg.paramFilter);
  const testParameter = normalizeTestParameter(cfg.testParameter);
  const paramExclude =
    typeof cfg.paramExclude === 'string' && cfg.paramExclude.trim() ? cfg.paramExclude.trim().slice(0, 200) : null;
  const hasFilter = !!paramFilter;
  const hasTest = !!testParameter;
  const hasExclude = !!paramExclude;
  if (!hasFilter && !hasTest && !hasExclude) return points;
  let out = points;
  const available = () =>
    [...new Set(out.map((p) => `${p.location}:${p.param}`))].join('、') || '（无）';

  if (hasFilter) {
    const want = new Set(paramFilter);
    const filtered = out.filter((p) => want.has(p.location));
    if (!filtered.length) {
      throw new AppError(
        ErrorCode.INVALID_PARAM,
        `--param-filter=${paramFilter.join(',')} 没有匹配到任何注入点` +
          `（可用位置：${[...new Set(out.map((p) => p.location))].join('、') || '无'}）`
      );
    }
    out = filtered;
  }

  if (hasTest) {
    const want = new Set(testParameter.map((s) => String(s).toLowerCase()));
    const filtered = out.filter((p) => want.has(String(p.param).toLowerCase()));
    if (!filtered.length) {
      throw new AppError(
        ErrorCode.INVALID_PARAM,
        `--test-param ${cfg.testParameter.join(',')} 没有匹配到任何注入点（可用点位：${available()}）`
      );
    }
    out = filtered;
  }

  if (hasExclude) {
    let re;
    try {
      re = new RegExp(cfg.paramExclude, 'i');
    } catch (e) {
      throw new AppError(
        ErrorCode.INVALID_PARAM,
        `--param-exclude 不是合法正则：${e?.message || e}`
      );
    }
    const filtered = out.filter((p) => !re.test(String(p.param)));
    if (!filtered.length) {
      throw new AppError(
        ErrorCode.INVALID_PARAM,
        `--param-exclude /${cfg.paramExclude}/i 把全部注入点都排除了（可用点位：${available()}）` +
          '—— 这通常意味着正则写得太宽，已拒绝启动 0 点扫描'
      );
    }
    out = filtered;
  }

  return out;
}
