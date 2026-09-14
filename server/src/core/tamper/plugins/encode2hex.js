// 全量十六进制编码：将整个 payload 编码为十六进制（对标 sqlmap encode2hex.py）
// 注意：此插件会破坏所有非十六进制字符，仅适用于特定场景
export const encode2hex = {
  name: 'encode2hex',
  description: '将整个 payload 编码为十六进制，绕过 WAF 检测',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return Buffer.from(String(payload ?? '')).toString('hex');
  },
};
export default encode2hex;
