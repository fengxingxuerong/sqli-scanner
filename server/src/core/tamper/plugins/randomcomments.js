// 关键字后插 /**/ 注释，变形关键字结构（绕过关键字整词规则）
//
// ⚠️ [2026-10-08 D14 撤回] 本件曾于 D12 改成上游 sqlmap 1.10.10 的**词内**随机切分
//   （`INSERT` → `I/**/NS/**/ERT`），理由是"词后追加保留整词 ⇒ 对整词规则等于没变"。
//   离线矩阵（CRS 离线 12 类）确实从 16.7% 涨到 50%，但**真机把它证伪了**：
//     CI dispatch（`modsec-live` / `tamper-waf-matrix`，记录见 CHANGELOG 2026-10-07
//     「D12 真机补验留证」）：本件**直连上界 10/19 → 0/19**。
//   机理不难确认：MySQL 词法把注释当**分隔符**，`SEL/**/ECT` 是两个标识符
//   （`SEL` `ECT`）而不是 `SELECT` ⇒ 整条 SQL 语法错误。上游形态在真 MySQL 上根本解析不了。
//   ⇒ 离线"规则命中"涨了、真机"还能不能执行"归零 —— 正是本仓反复记的「放行 ≠ 打穿」，
//   只不过这次掉的是**语义活力**那一头。故默认件还原为词后追加（保住真机上界）。
// 词内拆分的**固定切点**那一面由 keywordSplit 承担（/*!*/ 是 MySQL 版本注释，
//   词法上是合法注释且不切词，与本件形态不同）。上游词内形态本仓**不采纳、也不另立变体**
//   —— 一个在真库上必然语法错误的变换入库只会污染矩阵（D7 判 `equaltorlike` 为"废插件"
//   是同一条标准）。
import { SQL_KEYWORDS } from '../keywords.js';

export const randomcomments = {
  name: 'randomcomments',
  description: '在 SQL 关键字后插入 /**/ 注释，变形关键字结构（词内切分已在真机上被证伪，不采纳）',
  doctests: [
    { input: 'SELECT 1', output: 'SELECT/**/ 1' },
    { input: '1 UNION ALL SELECT NULL', output: '1 UNION/**/ ALL/**/ SELECT/**/ NULL/**/' },
    // 反向钉子：绝不在关键字**词内**插注释（真机 上界 10/19 → 0/19 的教训）
    { input: 'INSERT', output: 'INSERT/**/' },
    { input: 'foo bar', output: 'foo bar' },
  ],
  /**
   * @param {string} payload
   * @returns {string}
   */
  transform(payload) {
    return String(payload ?? '').replace(/\b([A-Za-z_]+)\b/g, (m, word) =>
      (SQL_KEYWORDS.has(word.toUpperCase()) ? `${word}/**/` : m));
  },
};
export default randomcomments;
