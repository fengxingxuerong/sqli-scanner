// 空 payload 保护：对空 payload 注入占位符，确保检测器不因空输入而崩溃（对标 sqlmap nonempty.py）
export const nonempty = {
  name: 'nonempty',
  description: '对空 payload 注入占位符，确保检测器不因空输入而崩溃',
  transform(payload, ctx) {
    const s = String(payload ?? '');
    if (!s || s.trim().length === 0) {
      return "'1'='1";
    }
    return s;
  },
};
export default nonempty;