// ============================================================================
// channelPolicy.js —— 「通道降级编排」（A3）
// ============================================================================
// 解决什么：扫描调度（`engine/scan/detect.js`）的通道顺序是**写死的**两层
//   FAST = [union, error, boolean, inline] / SLOW = [time, stacked, oob]
// —— 它对「目标实际拦了什么」一无所知。逐词画像（blockProfile.profileBlockedTokens）
// 早在 A2 就有了，但它的产出 `profile.blocked` 是 chainVerify 的**局部变量**，
// 函数只返回 chain，画像在验链结束时被丢弃 → 调度层永远拿不到。
// 结果是：即便 WAF 明确拦 `union`/`select`，union 通道照样发满整包 payload，
// 跑完才知道 miss，再靠「重跑」补救。
//
// 本模块做一件事：**把画像翻译成通道级决策**——哪些通道在当前拦截画像下
// 「注定跑不出结论」，从而不该再发整包请求。
//
// ★保守纪律★（宁可多跑，不可漏检）：
//   ① 无画像（blocked 为空）→ 全部保留，不决策（拿不到证据就不编排）；
//   ② 只有某通道**必需组整组被拦**、且当前 tamper 链**不消除该组任一 token** 才降级；
//   ③ 未知技术（不在 CHANNEL_TOKENS 里）→ 一律保留（新接入的通道不猜）。
//
// ⚠️ 诚实边界：`required` 里的 token 是**语义上不可替代**的最小集，不是该通道
// payload 里出现的全部记号。故本模块的结论是「此通道在当前形态下无望」，
// 不等于「此点无此漏洞」——降级只影响请求预算，不参与漏洞结论判定。
// ============================================================================

/**
 * 各检测通道 → 它**语义上不可替代**的 token 组。
 *
 * 结构：`required` 为**合取范式**——外层 AND、内层 OR。
 * 例：boolean 的 `[['and','or']]` 表示「and 与 or 都被拦」才算死（只拦 and 时
 * 还有 OR 形态可用，且 `symboliclogical` 等链能把二者改写为 `&&`/`||`）。
 *
 * `aux` 仅供日志/报告解释用，不参与降级判定：这些记号都有等价替代写法
 * （空格→`/**​ /`、注释 `--`→`#`、逗号→`JOIN`/`CASE`），拦了不代表通道死。
 *
 * token id 取自 blockProfile.TOKEN_PROBES（quote/comment/hash/space/and/or/
 * union/select/sleep/paren/comma/cmp）。
 */
export const CHANNEL_TOKENS = {
  // UNION 查询：没有 union 与 select 就无法构造集合查询（记忆里的死路：
  // 「绕开 union 字面量」5 类手法均已实测排空 → 二者皆拦即无望）
  union: { required: [['union', 'select']], aux: ['space', 'comma', 'paren'] },
  // 报错注入：靠闭合引号制造语法错误，引号被拦且链不消除 → 无从触发
  error: { required: [['quote']], aux: ['paren', 'comma', 'space'] },
  // 布尔盲注：真假两态靠 AND/OR 构造；二者皆拦则无法构造对照
  boolean: { required: [['and', 'or']], aux: ['space', 'cmp', 'comment', 'hash'] },
  // 内联注入：同 error，依赖闭合引号
  inline: { required: [['quote']], aux: ['space'] },
  // 时间盲注：SLEEP/BENCHMARK 是延时载体，被拦即无法测时
  time: { required: [['sleep']], aux: ['paren', 'comma', 'space'] },
  // 堆叠查询：需闭合引号后接分号与新语句
  stacked: { required: [['quote']], aux: ['comment', 'hash', 'space'] },
  // 带外通道：需闭合引号后拼带外函数名
  oob: { required: [['quote']], aux: ['space', 'paren'] },
};

/**
 * 画像 → 通道级决策（纯函数，零请求）。
 *
 * @param {object} p
 * @param {string[]} [p.techniques] 待调度的技术名（如 ['union','error','boolean']）
 * @param {string[]} [p.blocked] 逐词画像输出的被拦 token id 列表
 * @param {string[]|Set<string>} [p.covered] 当前 tamper 链能消除的 token 集合
 *   （blockProfile.coveredTokens(plugins) 的输出）
 * @returns {{run: string[], skipped: Array<{technique: string, deadTokens: string[], reason: string}>}}
 *   同分保持入参顺序（稳定）；`run` 是 techniques 的子集。
 */
export function planChannels({ techniques = [], blocked = [], covered = [] } = {}) {
  const list = Array.isArray(techniques) ? techniques.filter((t) => typeof t === 'string') : [];
  const blockedSet = new Set(Array.isArray(blocked) ? blocked : []);
  const coveredSet = covered instanceof Set ? covered : new Set(Array.isArray(covered) ? covered : []);

  const run = [];
  const skipped = [];

  // ① 无画像 → 不决策（拿不到证据就不编排，零回归）
  if (blockedSet.size === 0) return { run: list.slice(), skipped };

  for (const t of list) {
    const spec = CHANNEL_TOKENS[t];
    // ③ 未知技术 → 一律保留（新接入的通道不猜，防"未登记即被降级"）
    if (!spec || !Array.isArray(spec.required) || spec.required.length === 0) {
      run.push(t);
      continue;
    }
    // ② 只要存在一组「整组被拦 且 链不消除该组任一 token」→ 该通道判死
    const dead = spec.required.find(
      (group) =>
        Array.isArray(group) &&
        group.length > 0 &&
        group.every((tok) => blockedSet.has(tok)) &&
        !group.some((tok) => coveredSet.has(tok))
    );
    if (dead) {
      skipped.push({
        technique: t,
        deadTokens: [...dead],
        reason: `必需记号 [${dead.join('|')}] 全部被拦，且当前 tamper 链不消除其中任一记号`,
      });
    } else {
      run.push(t);
    }
  }
  return { run, skipped };
}

export default { planChannels, CHANNEL_TOKENS };
