// 全量十进制编码：将整个 payload 编码为十进制数字序列（对标 sqlmap encode2dec.py）
export const encode2dec = {
  name: 'encode2dec',
  description: '将整个 payload 编码为十进制数字序列，绕过 WAF 检测',
  transform(payload, ctx) {
    const src = String(payload ?? '');
    return src.split('').map(c => String(c.charCodeAt(0))).join(' ');
  },
};
export default encode2dec;