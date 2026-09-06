// 0x<hex> 串 → CONCAT(CHAR(),...) 等价写法（对标 sqlmap hex2char.py）
// 把 MySQL 十六进制字符串字面量改写为 CHAR() 函数拼接，绕过「只做字符级
// 大小写归一/去十六进制前缀」的 WAF（如将 0x 前缀剥离后校验的场景）。
export const hex2char = {
  name: 'hex2char',
  description: '将 MySQL 0x<hex> 字面量替换为 CONCAT(CHAR(),...) 等价写法',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return payload.replace(/\b0x([0-9a-f]+)\b/gi, (whole, hex) => {
      const bytes = [];
      for (let i = 0; i < hex.length; i += 2) {
        bytes.push(parseInt(hex.slice(i, i + 2), 16));
      }
      if (bytes.length > 1) return `CONCAT(${bytes.map((b) => `CHAR(${b})`).join(',')})`;
      return `CHAR(${bytes[0]})`;
    });
  },
};

export default hex2char;
