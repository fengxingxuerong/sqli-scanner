// =====================================================================
// capabilityConstraints.js — 汇总「本次扫描被抑制了什么能力」写进
// report.summary.constraints（collectCapabilityConstraints，独立纯函数）。
// 自 ScanManager.js 拆出（纯搬移）：ScanManager.js 保持 re-export（guards.production
// 等测试仍从原路径导入），start() 内调用点不变。
// =====================================================================
import { defaults } from '../../config/defaults.js';
import { countDestructiveCandidates, registryMode } from '../payloadRegistry.js';

/**
 * [P0-FIX 2026-09-09] 汇总「本次扫描被抑住了什么能力」，写进 report.summary.constraints。
 *
 * 为什么需要：本项目反复出现同一类缺陷——开关存在、引擎支持、中间断链，而用户以为生效了。
 * 把「没做」显式写出来，质控与交付时才能回答「你到底测了什么」；一句「已按最高风险等级测试」
 * 在没投放高危池时就是不实陈述。仅记真实可抑制项：当前 level/risk 本来就投不到高危模板时不记，
 * 免得给人一条假线索去改无关开关。
 *
 * @param {object} config 扫描配置（target.config）
 * @param {object} [target] 扫描目标（需要 cookieParams/headerParams 才能判断"参数给了但没测"）
 * @returns {string[]} 可读说明（空数组 = 本次无任何能力被抑制）
 */
export function collectCapabilityConstraints(config = {}, target = {}) {
  const out = [];
  const productionMode = config.productionMode !== false;
  const confirmDestructive = config.confirmDestructive === true;
  const risk = Number(config.risk) || Number(defaults.risk) || 2;
  const level = Number(config.level) || Number(defaults.level) || 1;
  const useRegistry = registryMode(config);

  if (productionMode && !confirmDestructive) {
    let n = 0;
    try {
      n = countDestructiveCandidates({ level, risk, testFilter: config.testFilter, testSkip: config.testSkip });
    } catch {
      n = 0;
    }
    if (n > 0) {
      out.push(
        `高危 payload 池（写文件/RCE/重运算类，本配置下候选 ${n} 条）已抑制：` +
          'productionMode=true 且未 confirmDestructive=true。确需在已授权目标上投放时显式设 confirmDestructive=true；' +
          '靶场/演练环境可整体关护栏（productionMode=false）'
      );
    }
  }
  if (!useRegistry && risk >= 3) {
    out.push(
      '扁平 payload 路径（useRegistry=false）不经过注册表高危池门控：REST/UI 下高危向量根本不会投放'
        + '（只允许 CLI 的 --risk 3 + --confirm-destructive 显式合并到进程级 payload 池）。' +
        '要真正拿到 risk=3 语义请用 useRegistry=true（受本护栏约束）或走 CLI 双开关'
    );
  }
  // testFilter/testSkip 是**注册表条目的属性**（按 entry.id 过滤）：扁平路径下这两个键没有任何读取点。
  // 此前 time 通道默认走注册表（另三个走扁平），所以用户设了 --test-filter 会得到「只筛了一条通道」
  // 的结果而无处可见。三通道判定点统一后，这里把「完全没生效」这一侧也讲明白。
  if (!useRegistry && (config.testFilter || config.testSkip)) {
    out.push(
      `--test-filter/--test-skip 未生效（本次收到 ${config.testFilter ? `filter=${config.testFilter}` : ''}${config.testFilter && config.testSkip ? ' ' : ''}${config.testSkip ? `skip=${config.testSkip}` : ''}）：` +
        '过滤条件作用于声明式注册表条目，扁平 payload 路径没有读取点。确需按 id 精选向量请同时设 useRegistry=true（CLI：--use-registry）'
    );
  }
  const so = config.secondOrder && typeof config.secondOrder === 'object' ? config.secondOrder : {};
  if (so.enabled === true && productionMode && so.allowWrites !== true) {
    out.push(
      '二阶非幂等写请求（POST/PUT/PATCH/DELETE）已抑制：productionMode=true 时需 secondOrder.allowWrites=true。' +
        '未放行时只跑幂等方法（GET/HEAD/OPTIONS），存储型写路径可能测不到'
    );
  }
  if (config.enableExtract === true) {
    out.push(
      '本次开启拖库（enableExtract）：提取阶段会向目标发出大量读请求（受限速与行数上限约束）。' +
        '生产环境建议控制行数并避开业务高峰'
    );
  }
  // [P0-FIX 2026-09-28 接口靶场] 调用方给了 cookieParams / headerParams，但 level 不够时
  //   TargetParser 根本不会把它们变成注入点（cookie 需 level≥2、header 需 level≥3 或
  //   testHeaders，见 engine/TargetParser.js:117-136）。后果是接口层最坏的一类形状：
  //   请求 200、扫描跑完、报告写「未检出」，而"我明明传了 Cookie 参数"这一线索完全消失。
  //   口径与 CLI 一致（--level 决定测不测 cookie/header），这里只负责把"没测"喊出来。
  const levelNum = Number(level) || 1;
  const cookieKeys = Object.keys(target.cookieParams || {});
  if (cookieKeys.length && levelNum < 2) {
    out.push(
      `cookieParams 未被测试（收到 ${cookieKeys.length} 个：${cookieKeys.slice(0, 5).join(', ')}）：` +
        `cookie 注入点需 level≥2，本次 level=${levelNum}。要测 Cookie 请设 config.level=2（CLI：--level 2）`
    );
  }
  const headerKeys = Object.keys(target.headerParams || {});
  if (headerKeys.length && levelNum < 3 && config.testHeaders !== true) {
    out.push(
      `headerParams 未被测试（收到 ${headerKeys.length} 个：${headerKeys.slice(0, 5).join(', ')}）：` +
        `header 注入点需 level≥3（或 config.testHeaders=true），本次 level=${levelNum}`
    );
  }
  return out;
}
