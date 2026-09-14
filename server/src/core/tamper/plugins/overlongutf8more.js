// 对标 sqlmap overlongutf8more.py：将所有字符转为超长 UTF-8 编码
// SELECT -> %C1%93%C1%85%C1%8C%C1%85%C1%83%C1%94；已编码 %XX 序列保持原样
export const overlongutf8more = {
  name: 'overlongutf8more',
  description: '将所有字符转为超长 UTF-8 编码（%C1%93 类，绕过字符级 WAF 匹配）',
  doctests: [
    { input: '2>1', output: '%C0%B2%C0%BE%C0%B1' },
    { input: 'a', output: '%C1%A1' },
    { input: '%41', output: '%41' }, // 已编码序列保持原样
  ],
  /**
   * @param {string} payload
   * @returns {string}
   */
  transform(payload) {
    const s = String(payload ?? '');
    if (!s) return s;
    let out = '';
    for (let i = 0; i < s.length; i++) {
      const ch = s[i];
      // 已编码 %XX 序列原样保留
      if (ch === '%' && i < s.length - 2 && /[0-9a-fA-F]/.test(s[i + 1]) && /[0-9a-fA-F]/.test(s[i + 2])) {
        out += s.slice(i, i + 3);
        i += 2;
        continue;
      }
      // codePointAt 的返回类型含 undefined；此处 i < s.length 已保证有效索引
      const ordinal = /** @type {number} */ (s.codePointAt(i));
      if (ordinal > 0xffff) i++; // 代理对
      if (ordinal < 0x80) {
        // 超长 UTF-8：双字节表示单字节 ASCII
        out += '%' + (0xc0 + (ordinal >> 6)).toString(16).toUpperCase().padStart(2, '0');
        out += '%' + (0x80 + (ordinal & 0x3f)).toString(16).toUpperCase().padStart(2, '0');
      } else {
        // 非 ASCII：常规 UTF-8 字节序列
        const bytes = Buffer.from(String.fromCodePoint(ordinal), 'utf8');
        for (const b of bytes) out += '%' + b.toString(16).toUpperCase().padStart(2, '0');
      }
    }
    return out;
  },
};
export default overlongutf8more;
