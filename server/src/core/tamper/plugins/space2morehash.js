// 空格 → #<随机串>%0A（MySQL 行注释）+ 关键字后追加（对标 sqlmap space2morehash.py）
// 引号感知：跳过字符串字面量内的空格/关键字，遇行注释（# 或 -- ）保持剩余原文。
// 关键点：仅在 SQL 关键字后追加注释块，避免破坏字符串字面量语义。
import { SQL_KEYWORDS } from '../keywords.js';
import { isQuoteEscaped } from '../quoteScan.js';

function randStr() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
  const n = 6 + Math.floor(Math.random() * 7); // 6-12 位（对标 sqlmap random.randint(6,12)）
  let out = '';
  for (let i = 0; i < n; i++) out += chars[Math.floor(Math.random() * chars.length)];
  return out;
}

export const space2morehash = {
  name: 'space2morehash',
  description: '将空格替换为 #<随机串>%0A 并在 SQL 关键字后追加（MySQL 行注释），绕过空格过滤',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    const src = String(payload ?? '');
    if (!src) return src;

    // pass 1：引号感知的关键字扫描——关键字后追加 #<rand>%0A（后随非单词字符且非 '(' 时）
    let s = '';
    let inSingle = false;
    let inDouble = false;
    let word = '';
    const emit = (appendAllowed) => {
      if (word) {
        const isKw = SQL_KEYWORDS.has(word.toUpperCase());
        s += appendAllowed && isKw ? `${word}%23${randStr()}%0A` : word;
        word = '';
      }
    };
    // [2026-10-05 修复] 转义引号判别原来只看前一个字符：`src[i-1] !== '\\'`。
    // 那是错的 —— `'x\'` 里的结尾 `'` **前面是反斜杠但并未被转义**（反斜杠本身
    // 已被 `'x\\'` 的 `\\` 成对消费），真正的判据是**连续反斜杠的奇偶性**：
    //   'a\'    1 个反斜杠 ⇒ 引号被转义，不闭合
    //   'a\\'   2 个       ⇒ 引号未转义，闭合
    // 原实现把后两种都判成"被转义" ⇒ 引号状态永不闭合 ⇒ 该引号之后的所有字符
    // 都被当成字符串字面量：关键字不再追加混淆块（AND/SLEEP 原样发出，直接撞 WAF），
    // pass 2 的空格替换也一并失效（见 e2e 回归用例）。
    // MySQL/MSSQL 默认反斜杠转义，payload 里 `'x\'` 极常见，故这不是边角情况。
    //
    // [2026-10-05 收敛] 判据已抽到 core/tamper/quoteScan.js 作为**单一真源**
    // （isQuoteEscaped / readSqlLiteral / splitByLiteral）。此处原有一份本地
    // isEscaped 拷贝 —— 实现正确但仍是第二份副本：quoteScan 若修 bug（例如将来
    // 扩展到 MySQL 的 NO_BACKSLASH_ESCAPES 模式），这里会静默留在旧行为。
    // "同一判据多份实现，必然只改一处" —— 与 tamper/plugins 下 51 个状态机的
    // 收敛是同一条理由。语义完全等价，已由 tests/tamperUnclosedLiteral.test.js
    // 与本文件的既有行为一并回归。
    // 刻意**直接调用** isQuoteEscaped，而不是先 `const isEscaped = isQuoteEscaped`
    // 再转调：别名会让「导入了但没改」的半迁移状态在源码上看不出来 ——
    // tests/tamperQuoteScanAdoption.test.js 的守卫-2（import 了就必须真的调用到）
    // 正是为此存在，一行别名就足以让它变成摆设。多一层间接没换来任何好处。
    for (let i = 0; i <= src.length; i++) {
      if (i === src.length) {
        emit(true);
        break;
      }
      const ch = src[i];
      if (ch === "'" && !isQuoteEscaped(src, i)) {
        emit(true);
        inSingle = !inSingle;
        s += ch;
        continue;
      }
      if (ch === '"' && !isQuoteEscaped(src, i)) {
        emit(true);
        inDouble = !inDouble;
        s += ch;
        continue;
      }
      if (inSingle || inDouble) {
        s += ch;
        continue;
      }
      if (/[A-Za-z0-9_]/.test(ch)) {
        word += ch;
        continue;
      }
      emit(ch !== '(');
      s += ch;
    }

    // pass 2：引号外空格 → #<rand>%0A；遇行注释保持剩余原文
    let out = '';
    let q1 = false;
    let q2 = false;
    for (let i = 0; i < s.length; i++) {
      const ch = s[i];
      if (ch === "'" && !isQuoteEscaped(s, i)) q1 = !q1;
      else if (ch === '"' && !isQuoteEscaped(s, i)) q2 = !q2;
      if (!q1 && !q2) {
        if (ch === '#' || (ch === '-' && s[i + 1] === '-' && s[i + 2] === ' ')) {
          out += s.slice(i);
          break;
        }
        if (ch === ' ' || ch === '\t') {
          out += `%23${randStr()}%0A`;
          continue;
        }
      }
      out += ch;
    }
    return out;
  },
};

export default space2morehash;
