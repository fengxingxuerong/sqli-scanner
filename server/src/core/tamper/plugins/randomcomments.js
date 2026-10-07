// 关键字**内部**随机插 /**/ 注释（对标 sqlmap 1.10.10 tamper/randomcomments.py）
//
// [T-10 2026-10-07] 旧实现只在关键字**之后**追加 `/**/`（`SELECT` → `SELECT/**/`），
//   而上游是在关键字**词内**随机切分（`INSERT` → `I/**/NS/**/ERT`）。差别不是排版：
//   词内切分会破坏"关键字整词"的形态，词后追加则完整保留了整词 ⇒ 对
//   `\bSELECT\b` 型的整词规则，旧形态等于没变。
//   词内拆分面此前由 keywordSplit 承担（固定切中点），本件补的是**随机位置**那一面
//   （固定切点会被针对性归一化规则吃干净）。
// 随机性：默认 Math.random；`ctx.rng` 可注入 0..1 的函数 ⇒ 测试可确定性断言
//   （上游用 sqlmap 自己的 randomRange，判据同样只能靠 seed）。
import { SQL_KEYWORDS } from '../keywords.js';

export const randomcomments = {
  name: 'randomcomments',
  description: '在 SQL 关键字内部随机插入 /**/ 注释，破坏关键字整词匹配',
  doctests: [
    // 输出含随机性 ⇒ 用 match 断言形态：词内至少有一处 /**/，且字母顺序不变
    { input: 'INSERT', match: '^I(/\\*\\*/)?N(/\\*\\*/)?S(/\\*\\*/)?E(/\\*\\*/)?R(/\\*\\*/)?T$' },
  ],
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    const src = String(payload ?? '');
    if (!src) return src;
    const rng = (ctx && typeof ctx.rng === 'function') ? ctx.rng : Math.random;
    const words = [...new Set(src.match(/\b[A-Za-z_]+\b/g) || [])];
    let out = src;
    for (const word of words) {
      if (word.length < 2) continue;
      if (!SQL_KEYWORDS.has(word.toUpperCase())) continue;
      let built = word[0];
      for (let i = 1; i < word.length - 1; i++) {
        built += `${rng() < 0.5 ? '/**/' : ''}${word[i]}`;
      }
      built += word[word.length - 1];
      // 上游：一处都没切中 ⇒ 强制在内部随机切一刀，保证形态一定改变
      if (!built.includes('/**/')) {
        const idx = 1 + Math.floor(rng() * (word.length - 1));
        built = `${word.slice(0, idx)}/**/${word.slice(idx)}`;
      }
      out = out.replace(new RegExp(`\\b${word}\\b`, 'g'), built);
    }
    return out;
  },
};
export default randomcomments;
