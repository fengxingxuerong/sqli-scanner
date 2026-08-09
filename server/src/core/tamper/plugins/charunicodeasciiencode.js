// 将 ASCII 字符（0x20-0x7E）转为 \uXXXX Unicode 转义（类名 charunicodeasciiencode）
// 用途：部分 WAF 不解码 Unicode 转义，而数据库字符串上下文会按码点还原，
//       从而让注入串"对人不可读、对库可执行"，绕过基于关键字的过滤。
export const charunicodeasciiencode = {
  name: 'charunicodeasciiencode',
  description: '将 ASCII 字符转为 \\uXXXX Unicode 转义（绕过不解码 Unicode 的 WAF）',
  transform(payload) {
    let out = '';
    for (const ch of payload) {
      const code = ch.codePointAt(0);
      if (code >= 0x20 && code <= 0x7e) {
        out += '\\u' + code.toString(16).toUpperCase().padStart(4, '0');
      } else {
        out += ch;
      }
    }
    return out;
  },
};

export default charunicodeasciiencode;
