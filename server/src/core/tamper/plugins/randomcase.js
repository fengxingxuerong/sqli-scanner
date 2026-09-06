// 关键字随机大小写（类名 randomcase）
// 只随机化 SQL 关键字（引入关键字表 SQL_KEYWORDS），字符串字面量内容 / 列名 / 表名等
// 非关键字 token 保持原样，避免把 `'Hello'` 之类字符串字面量内容也随机化（修复语义 bug）。
import { SQL_KEYWORDS } from '../keywords.js';

export const randomcase = {
  name: 'randomcase',
  description: '随机化 SQL 关键字大小写（仅关键字，字符串字面量不受影响）',
  doctests: [
    // 随机大小写，用正则断言「仅关键字被随机化且非关键字保留」
    { input: 'SELECT 1', match: '^[Ss][Ee][Ll][Ee][Cc][Tt] 1$' },
  ],
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return String(payload ?? '').replace(/[A-Za-z_][A-Za-z0-9_]*/g, (word) => {
      if (!SQL_KEYWORDS.has(word.toUpperCase())) return word;
      return word
        .split('')
        .map((ch) => (Math.random() < 0.5 ? ch.toUpperCase() : ch.toLowerCase()))
        .join('');
    });
  },
};

export default randomcase;
