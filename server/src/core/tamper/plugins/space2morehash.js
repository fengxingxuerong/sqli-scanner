// 空格 → #<随机串>%0A（MySQL 行注释）+ 关键字后追加（对标 sqlmap space2morehash.py）
// 引号感知：跳过字符串字面量内的空格/关键字，遇行注释（# 或 -- ）保持剩余原文。
// 关键点：仅在 SQL 关键字后追加注释块，避免破坏字符串字面量语义。
import { SQL_KEYWORDS } from '../keywords.js';

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
    for (let i = 0; i <= src.length; i++) {
      if (i === src.length) {
        emit(true);
        break;
      }
      const ch = src[i];
      if (ch === "'" && (i === 0 || src[i - 1] !== '\\')) {
        emit(true);
        inSingle = !inSingle;
        s += ch;
        continue;
      }
      if (ch === '"' && (i === 0 || src[i - 1] !== '\\')) {
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
      if (ch === "'" && (i === 0 || s[i - 1] !== '\\')) q1 = !q1;
      else if (ch === '"' && (i === 0 || s[i - 1] !== '\\')) q2 = !q2;
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
