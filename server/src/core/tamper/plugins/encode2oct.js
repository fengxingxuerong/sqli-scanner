// 全量八进制编码：将整个 payload 编码为八进制转义序列（对标 sqlmap encode2oct.py）
export const encode2oct = {
  name: 'encode2oct',
  description: '将整个 payload 编码为八进制转义序列，绕过 WAF 检测',
  transform(payload, ctx) {
    const src = String(payload ?? '');
    return src.split('').map(c => `\\${c.charCodeAt(0).toString(8).padStart(3, '0')}`).join('');
  },
};
export default encode2oct;