// ============================================================================
// pwnVerdict.mjs —— 真机对拍的**打穿判据**（单一来源，可被单测直接钉住）
//
// 为什么单独抽出来：这段逻辑决定「算不算打穿」，是本轮所有数字的根。
// 留在 modsec-live.mjs 里就没法被单测覆盖（导入它会直接执行 main 的副作用），
// 于是只能靠「读起来对」——本仓反复吃过这个亏（断言太浅 = 假绿）。
//
// ⚠️ 判据的核心纪律：**只采信 MySQL 自己生成的东西**
//   · 结果集标记必须出现在 `ROWS:` 开头的 body 里
//   · 报错证据必须是 MySQL 生成的固定短语
//   理由：echo 靶站会把 payload 原样回显，任何「body 里出现 payload」
//   形态的判据在 echo 下**恒真**（巧合陷阱）。守卫用例专门钉这两条反例。
// ============================================================================

/** 抵达 SQL 层：靶站（真库模式）在 body 前缀标注来源 */
export const SQL_LAYER = /^(ROWS|SQLERR):/;

/** ① 结果集取数的证据形态（与 samples.mjs 的标记一一对应） */
export const EXFIL_RESULT = /__S__[^;|]*__E__|SQLISCANNER\d/;

/** ② 报错取数的证据形态：MySQL 生成的短语，payload 里不含这些字样 */
export const EXFIL_ERROR = /XPATH syntax error|Duplicate entry/i;

/**
 * 单次响应的判定层级：
 *   unknown      网络异常（status 0）
 *   blocked      被 WAF 拦（非 2xx）
 *   echo         到了后端但不是真库（无 SQL 层证据）→ 本轮打穿不可判定
 *   reached_sql  真跑了 SQL（成功或报错）但没取到证据
 *   pwn_result   结果集里取到注入数据
 *   pwn_error    报错消息里带出注入数据
 */
export function verdict(r) {
  if (!r || r.status === 0) return 'unknown';
  if (r.status >= 400) return 'blocked';
  const b = r.text || '';
  if (!SQL_LAYER.test(b)) return 'echo';
  if (b.startsWith('ROWS:') && EXFIL_RESULT.test(b)) return 'pwn_result';
  if (b.startsWith('SQLERR:') && EXFIL_ERROR.test(b)) return 'pwn_error';
  return 'reached_sql';
}

/** 打穿（真正取到数据）—— 主口径 */
export const isPwn = (v) => v === 'pwn_result' || v === 'pwn_error';

/** 抵达 SQL 层（辅助口径） */
export const atSql = (v) => v === 'reached_sql' || isPwn(v);
