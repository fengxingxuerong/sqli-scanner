// 空格 -> 内联注释 /**/，绕过空格过滤（类名 space2comment）
// 引号状态机（P3）：跳过字符串字面量（'...'/"..."/`...`）内的空格与注释区，避免破坏 payload 语义。
// 修复场景：`'foo bar'` 原实现会变成 `'foo/**/bar'`（改写了字符串值）；行注释 `-- -` 后的
// 空格被替换也会让注释失效。现在引号内/注释区内空格一律保留原样。
export const space2comment = {
  name: 'space2comment',
  description: '将空格替换为内联注释 /**/，绕过空格过滤（引号状态机保护字符串字面量）',
  doctests: [
    { input: 'a AND b', output: 'a/**/AND/**/b' },
    { input: "'foo bar'", output: "'foo bar'" }, // 字符串字面量内空格不替换
  ],
  /**
   * @param {string} payload 待混淆的注入串
   * @param {object} ctx 检测上下文（透传，便于高级插件按 dbms 决策）
   * @returns {string}
   */
  transform(payload, ctx) {
    const src = String(payload ?? '');
    let out = '';
    // 状态：单引号 / 双引号 / 反引号（MySQL 标识符）/ 行注释（-- 与 #）/ 块注释（/* */）
    let inSingle = false;
    let inDouble = false;
    let inBacktick = false;
    let inLine = false;
    let inBlock = false;

    for (let i = 0; i < src.length; i++) {
      const ch = src[i];
      const prev = src[i - 1];

      if (inLine) {
        out += ch;
        if (ch === '\n') inLine = false;
        continue;
      }
      if (inBlock) {
        out += ch;
        if (ch === '/' && prev === '*') inBlock = false;
        continue;
      }
      if (inSingle) {
        out += ch;
        if (ch === "'" && prev !== '\\') inSingle = false;
        continue;
      }
      if (inDouble) {
        out += ch;
        if (ch === '"' && prev !== '\\') inDouble = false;
        continue;
      }
      if (inBacktick) {
        out += ch;
        if (ch === '`' && prev !== '\\') inBacktick = false;
        continue;
      }

      // 正常态：进入各状态或处理空格
      if (ch === "'") {
        inSingle = true;
        out += ch;
      } else if (ch === '"') {
        inDouble = true;
        out += ch;
      } else if (ch === '`') {
        inBacktick = true;
        out += ch;
      } else if (ch === '-' && src[i + 1] === '-') {
        inLine = true;
        out += ch;
      } else if (ch === '#') {
        inLine = true;
        out += ch;
      } else if (ch === '/' && src[i + 1] === '*') {
        inBlock = true;
        out += ch;
      } else if (ch === ' ') {
        out += '/**/';
      } else {
        out += ch;
      }
    }
    return out;
  },
};

export default space2comment;
