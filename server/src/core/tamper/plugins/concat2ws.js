// CONCAT() → CONCAT_WS() 转换，绕过 CONCAT 过滤（对标 sqlmap concat2ws.py）
// 注意：CONCAT_WS 第一个参数为分隔符，转换后使用空串 '' 保持语义等价
export const concat2ws = {
  name: 'concat2ws',
  description: '将 CONCAT() 替换为 CONCAT_WS(\'\',...)，绕过 CONCAT 关键字过滤',
  transform(payload, ctx) {
    return String(payload ?? '').replace(/CONCAT\s*\(/gi, (match) => {
      const isLower = match[0] === 'c';
      return isLower ? "concat_ws(''," : "CONCAT_WS('',";
    });
  },
};
export default concat2ws;