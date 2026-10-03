// =====================================================================
// hashAnalysis.js — 凭据哈希的**离线识别 + 风险标注**（纯函数，零依赖）
// =====================================================================
// 解决什么问题：`--passwords` 此前把 mysql.user / pg_shadow / sys.sql_logins 的
// `user:hash` 串原样丢进报告 —— 调用方拿到一坨十六进制，既不知道**是什么算法**，
// 也看不出**哪个账号有问题**。「读到了哈希」到「这条凭据值多少」之间缺一层判定。
//
// 本模块只做两件事（**不做爆破、不联网、不落盘**）：
//   ① 按各库真实的哈希格式识别算法（格式来源见下方 §格式表，逐条对应上游 SQL 的产出形态）；
//   ② 按 KDF 强度给出风险等级，并显式区分「空口令」这一独立语义。
//
// ★ 诚实边界（写进模块、也写进 README，不许在报告里含糊）★
//   · 「弱」= **该 KDF 在离线爆破下成本低**（无盐 MD5/SHA1、旧版 MySQL 16 hex 等），
//     不是「已经破解出了口令」。本模块**不做**任何字典/彩虹表尝试。
//   · 「空」可能有两种原因：账号确实无口令，或该账号使用**非口令认证插件**
//     （MySQL `auth_socket` / `sha256_password` 走 SSL 时 authentication_string 也为空）。
//     二者在 SQL 层不可区分，故只报「未设置口令或非口令插件」，不硬判「可空口令登录」。
//   · 只识别**格式**，不校验哈希是否自洽（例如 `*` + 40 hex 也照样匹配）；
//     格式对但内容被截断的目标，本模块无法发现 —— 那是提取层的 `--hex`/长度链的事。
// =====================================================================

/** 强度语义（单一维度，报告侧据此上色/排序；不要在别处另起一套口径） */
export const STRENGTH = /** @type {const} */ ({
  BLANK: 'blank',     // 哈希为空：未设口令 或 非口令认证插件
  WEAK: 'weak',       // 无盐或低成本的 KDF（离线爆破代价低）
  MEDIUM: 'medium',   // 有盐但算法老（SHA-1 / SHA1(SHA1) 等）
  STRONG: 'strong',   // 现代 KDF（bcrypt / argon2 / SCRAM / SHA-512+salt / SHA-2+cost）
  UNKNOWN: 'unknown', // 格式未识别 —— 不猜，如实标未知
});

/** 强度 → 风险等级（报告/清单共用，避免两处映射漂移） */
export function riskOfStrength(strength) {
  switch (strength) {
    case STRENGTH.BLANK: return 'high';
    case STRENGTH.WEAK: return 'high';
    case STRENGTH.MEDIUM: return 'medium';
    case STRENGTH.STRONG: return 'low';
    default: return 'unknown';
  }
}

/** 强度 → 中文标签（报告正文用） */
export const STRENGTH_LABEL = /** @type {Record<string,string>} */ ({
  [STRENGTH.BLANK]: '未设置口令 / 非口令插件',
  [STRENGTH.WEAK]: '弱（离线爆破成本低）',
  [STRENGTH.MEDIUM]: '中（有盐但算法偏老）',
  [STRENGTH.STRONG]: '强（现代 KDF）',
  [STRENGTH.UNKNOWN]: '未识别',
});

const HEX_RE = /^[0-9a-fA-F]+$/;

/**
 * 识别单个哈希串的算法与强度。
 * 判据只认**格式**（前缀/长度/字符集），不做任何内容校验 —— 见文件头「诚实边界」。
 * @param {string} hash 原始哈希串（可能为空串）
 * @returns {{ algo: string, label: string, strength: string }}
 */
export function classifyHash(hash) {
  const h = typeof hash === 'string' ? hash.trim() : '';
  if (!h) return { algo: 'none', label: '空', strength: STRENGTH.BLANK };

  // —— MySQL 8+ caching_sha2_password：$A$<3位迭代>$<salt+hash>（SHA-256 + 盐 + 迭代）——
  if (/^\$A\$[0-9]{3}\$/.test(h)) {
    return { algo: 'mysql-caching-sha2', label: 'MySQL caching_sha2_password（SHA-256 + 盐 + 迭代）', strength: STRENGTH.STRONG };
  }
  // —— MySQL native（* + 40 hex）= SHA1(SHA1(pw))，无盐 ——
  if (/^\*[0-9a-fA-F]{40}$/.test(h)) {
    return { algo: 'mysql-native-sha1', label: 'MySQL mysql_native_password（SHA1(SHA1)，无盐）', strength: STRENGTH.MEDIUM };
  }
  // —— MySQL ≤5.6 旧算法：16 hex（无盐，可被公开表秒破）——
  if (/^[0-9a-fA-F]{16}$/.test(h)) {
    return { algo: 'mysql-old-16hex', label: 'MySQL 旧版 16 hex（无盐）', strength: STRENGTH.WEAK };
  }
  // —— PostgreSQL SCRAM-SHA-256：SCRAM-SHA-256$<迭代>:<salt>$<StoredKey>:<ServerKey> ——
  if (/^SCRAM-SHA-256\$\d+:/.test(h)) {
    return { algo: 'pg-scram-sha-256', label: 'PostgreSQL SCRAM-SHA-256（加盐 + 迭代）', strength: STRENGTH.STRONG };
  }
  // —— PostgreSQL md5：md5 + 32 hex = MD5(password || username)，无盐 ——
  if (/^md5[0-9a-f]{32}$/i.test(h)) {
    return { algo: 'pg-md5', label: 'PostgreSQL md5（MD5(口令+用户名)，无盐）', strength: STRENGTH.WEAK };
  }
  // —— SQL Server 2012+：0x0200 + 4 字节盐 + SHA-512 ——
  if (/^0x0200[0-9a-fA-F]+$/i.test(h)) {
    return { algo: 'mssql-sha512', label: 'SQL Server 2012+（SHA-512 + 盐）', strength: STRENGTH.STRONG };
  }
  // —— SQL Server 2005/2008：0x0100 + 4 字节盐 + SHA-1 ——
  if (/^0x0100[0-9a-fA-F]+$/i.test(h)) {
    return { algo: 'mssql-sha1', label: 'SQL Server 2005/2008（SHA-1 + 盐）', strength: STRENGTH.MEDIUM };
  }
  // —— bcrypt / argon2 / sha512crypt / sha256crypt / md5crypt（少见但格式明确）——
  if (/^\$2[aby]?\$\d{2}\$/.test(h)) {
    return { algo: 'bcrypt', label: 'bcrypt（加盐 + 可调代价）', strength: STRENGTH.STRONG };
  }
  if (/^\$argon2(id|i|d)\$/.test(h)) {
    return { algo: 'argon2', label: 'Argon2（加盐 + 可调代价）', strength: STRENGTH.STRONG };
  }
  if (/^\$6\$/.test(h)) return { algo: 'sha512crypt', label: 'sha512crypt（$6$，加盐）', strength: STRENGTH.STRONG };
  if (/^\$5\$/.test(h)) return { algo: 'sha256crypt', label: 'sha256crypt（$5$，加盐）', strength: STRENGTH.STRONG };
  if (/^\$1\$/.test(h)) return { algo: 'md5crypt', label: 'md5crypt（$1$，加盐）', strength: STRENGTH.WEAK };
  if (/^\$P\$/.test(h)) return { algo: 'phpass', label: 'phpass（$P$，加盐 + 迭代）', strength: STRENGTH.MEDIUM };
  // —— LDAP 风格 {SCHEME}base64 ——
  if (/^\{SSHA\}/i.test(h)) return { algo: 'ldap-ssha', label: 'LDAP {SSHA}（SHA-1 + 盐）', strength: STRENGTH.MEDIUM };
  if (/^\{SHA\}/i.test(h)) return { algo: 'ldap-sha', label: 'LDAP {SHA}（SHA-1，无盐）', strength: STRENGTH.WEAK };
  if (/^\{MD5\}/i.test(h)) return { algo: 'ldap-md5', label: 'LDAP {MD5}（无盐）', strength: STRENGTH.WEAK };
  if (/^\{[A-Z0-9]+\}/i.test(h)) return { algo: 'ldap-other', label: 'LDAP 其它 scheme', strength: STRENGTH.UNKNOWN };

  // —— 裸 hex：只能按长度猜算法族，如实标「无盐」——
  if (HEX_RE.test(h)) {
    if (h.length === 32) return { algo: 'hex32-md5-or-ntlm', label: '裸 32 hex（MD5 / NTLM，无盐）', strength: STRENGTH.WEAK };
    if (h.length === 40) return { algo: 'hex40-sha1', label: '裸 40 hex（SHA-1，无盐）', strength: STRENGTH.WEAK };
    if (h.length === 64) return { algo: 'hex64-sha256', label: '裸 64 hex（SHA-256，无盐）', strength: STRENGTH.WEAK };
    return { algo: `hex${h.length}`, label: `裸 ${h.length} hex（未识别的算法族）`, strength: STRENGTH.UNKNOWN };
  }

  return { algo: 'unrecognized', label: '未识别格式', strength: STRENGTH.UNKNOWN };
}

/** 单条条目上限（防超大 mysql.user 把报告撑爆；超出部分只计数不入 entries） */
export const MAX_ENTRIES = 500;

/**
 * `--passwords` 的离线解读结果（analyzePasswords 的产出 / 报告读的结构）。
 * @typedef {Object} PasswordAnalysis
 * @property {number} total        参与统计的条目数（无冒号的行不计入）
 * @property {number} blank        空口令或非口令认证插件
 * @property {number} weak         弱（离线爆破成本低）
 * @property {number} medium       中（有盐但算法偏老）
 * @property {number} strong       强（现代 KDF）
 * @property {number} unknown      未识别格式
 * @property {Record<string, number>} algorithms 算法 → 条数
 * @property {Array<{ identity: string, user: string, host: string|null, algo: string, label: string, strength: string, risk: string }>} entries
 * @property {number} truncated    因超过 MAX_ENTRIES 而未入 entries 的条数
 */

/**
 * 解析凭据串（`user:hash` / `user@host:hash`，逗号分隔）并逐条标注风险。
 *
 * 分隔判据（对应上游 SQL 的真实产出形态）：
 *   · 条目分隔符 = `,` —— 三种库的哈希字符集（hex / base64+`$` / `:`）都不含逗号。
 *   · 身份与哈希 = **第一个** `:` —— 不能按最后一个切：PG SCRAM 的哈希内部含 `:`
 *     （`SCRAM-SHA-256$4096:salt$stored:server`），按最后一个切会把算法头撕进身份里。
 *   · MySQL 身份形如 `user@host`（上溯 CONCAT(user,0x40,host)），按**最后一个** `@` 拆。
 *
 * @param {string|null|undefined} raw extractScope 的 passwords 原始串
 * @param {{ dbms?: string|null }} [opts]
 * @returns {PasswordAnalysis|null}
 *   raw 为空/非字符串 ⇒ null（保持「未提取」与「提取为空」可区分）。
 */
export function analyzePasswords(raw, opts = {}) {
  if (typeof raw !== 'string' || raw.trim() === '') return null;

  const entries = [];
  const algorithms = /** @type {Record<string, number>} */ ({});
  let blank = 0, weak = 0, medium = 0, strong = 0, unknown = 0;
  let total = 0;

  for (const chunk of raw.split(',')) {
    const item = chunk.trim();
    if (!item) continue;
    // 无冒号 ⇒ 不是 `身份:哈希` 形态，跳过（不猜、不计入总数）
    const sep = item.indexOf(':');
    if (sep < 0) continue;

    const identity = item.slice(0, sep);
    const hash = item.slice(sep + 1);
    const { algo, label, strength } = classifyHash(hash);

    // 身份拆分：MySQL 是 `user@host`，PG/MSSQL 只有用户名
    const at = identity.lastIndexOf('@');
    const user = at > 0 ? identity.slice(0, at) : identity;
    const host = at > 0 ? identity.slice(at + 1) : null;

    total += 1;
    algorithms[algo] = (algorithms[algo] || 0) + 1;
    switch (strength) {
      case STRENGTH.BLANK: blank += 1; break;
      case STRENGTH.WEAK: weak += 1; break;
      case STRENGTH.MEDIUM: medium += 1; break;
      case STRENGTH.STRONG: strong += 1; break;
      default: unknown += 1; break;
    }

    // 有意**不回显原始哈希**：报告常在客户之间流转，分析小节不该凭空多出一份凭据副本。
    // 原始串仍在 report.data.passwords（既有行为，未变），本结构只是它的「解读」。
    if (entries.length < MAX_ENTRIES) {
      entries.push({ identity, user, host, algo, label, strength, risk: riskOfStrength(strength) });
    }
  }

  if (total === 0) return null;

  return {
    total,
    blank,
    weak,
    medium,
    strong,
    unknown,
    algorithms,
    entries,
    truncated: Math.max(0, total - entries.length),
  };
}

/** 风险标注是否「有值得说的东西」（全强 ⇒ 报告不渲染告警段，避免噪声） */
export function hasNotableRisk(analysis) {
  if (!analysis) return false;
  return analysis.blank > 0 || analysis.weak > 0 || analysis.unknown > 0;
}
