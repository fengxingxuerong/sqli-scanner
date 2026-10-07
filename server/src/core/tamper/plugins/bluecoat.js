// BlueCoat ProxySG 风格：关键字后插 %09，等号转 LIKE（绕过等号关键字规则）
//
// [T-2 2026-10-07] 对齐上游 sqlmap 1.10.10 tamper/bluecoat.py 的算法，顺带治掉
//   **叠出的双空白**：旧实现先把所有空格换成 `%09` 再把 `=` 换成 `' LIKE '`，
//   于是 `id = 1` 变成 `id%09 LIKE %091` —— tab 旁再跟一个真空格。
//   CRS 一类规则里「连续空白」本身就是特征（multiplespaces 型规则），
//   即"本想绕过、反而更像攻击"。上游的做法是三步：
//     ① 只在**SQL 关键字后**插 `%09`（保留原空格）
//     ② `\s*=\s*` → ` LIKE `（两侧空白一并吃掉，复合运算符 <=/>=/!= 跳过）
//     ③ 收尾折叠 `%09 ` → `%09`
//   ⇒ 空格与 %09 永不相邻，第二步的 LIKE 两侧恒为单个真空格。
// 注：旧实现"把所有空格都换掉"这一面由 space2* 族独立承担，不在此件重复。
import { SQL_KEYWORDS } from '../keywords.js';

export const bluecoat = {
  name: 'bluecoat',
  description: 'SQL 关键字后插入 %09、等号 = 替换为 LIKE，绕过 BlueCoat 类规则',
  doctests: [
    // 上游官方示例（tag 1.10.10）
    { input: 'SELECT id FROM users WHERE id = 1', output: 'SELECT%09id FROM%09users WHERE%09id LIKE 1' },
    // ② 复合运算符不得被拆坏，且 LIKE 两侧不得出现双空白
    { input: 'WHERE id>=1', output: 'WHERE%09id>=1' },
    { input: 'WHERE id = 1', output: 'WHERE%09id LIKE 1' },
  ],
  /**
   * @param {string} payload
   * @returns {string}
   */
  transform(payload) {
    let s = String(payload ?? '');
    // ① 关键字（全大写 token）后插 %09，原空格保留
    s = s.replace(/\b([A-Z_]+)(?=[^\w(]|$)/g, (m, word) =>
      (SQL_KEYWORDS.has(word.toUpperCase()) ? `${word}%09` : m));
    // ② 等号 → LIKE，两侧空白一并吃掉；复合运算符跳过（与 equaltolike 同锚点）
    s = s.replace(/\s*(?<![<>!=])=(?!=)\s*/g, ' LIKE ');
    // ③ 折叠 %09 后紧跟的空格
    return s.replace(/%09 /g, '%09');
  },
};
export default bluecoat;
