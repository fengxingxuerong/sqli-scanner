// ============================================================================
// http/logOnce.js —— 一次性日志（同 key 只打一次，防刷屏）
//
// 从 httpClient.js 拆出（2026-09-14 大文件二期拆分）。**纯搬移，行为不变**。
// 拆分原因：httpClient.js 已 1712 行（arch-guard 判定为技术债「只减不增」），
// 而这一组是**自包含的安全判定逻辑**，与 HTTP 传输层无耦合 → 抽成独立模块既过门禁，
// 也让 SSRF/代理规则可被单独测试。
// ============================================================================
import { logger } from '../logger.js';

const _onceLogged = new Set();
function logOnce(level, msg) {
  if (!msg || _onceLogged.has(msg)) return;
  if (_onceLogged.size > 64) _onceLogged.clear(); // 防无界增长（key 含 URL/上限等可变片段）
  _onceLogged.add(msg);
  try {
    logger[level](msg);
  } catch { /* 日志不可用不影响请求主流程 */ }
}
function infoOnce(msg) {
  logOnce('info', msg);
}

// 目标校验下放的统一文案（同一 key → warnOnce 天然去重）
const PROXY_DELEGATION_NOTE =
  '目标校验已下放至代理：本地跳过 DNS 解析与私网判定（仅保留 0.0.0.0/8、169.254.0.0/16、组播/保留段的 IP 字面量拒绝）。' +
  '请确认该代理为受控出口；如需恢复严格语义设 ssrfViaProxy="off"';

function warnInsecureTls() {
  logOnce(
    'warn',
    'insecureTls=true：已关闭 HTTPS 证书校验（自签/内网 CA 目标可扫），中间人攻击不再可辨 —— ' +
      '报告须注明本次扫描未校验证书；对未校验目标不再重试（见 NON_RETRYABLE_CODES）'
  );
}

export { logOnce, infoOnce, warnInsecureTls, PROXY_DELEGATION_NOTE };
