// 注释 → 空格：将内联注释 /**/ 替换为空格（对标 sqlmap comment2space.py）
export const comment2space = {
  name: 'comment2space',
  description: '将内联注释 /**/ 替换为空格，绕过 WAF 对注释的检测',
  transform(payload, ctx) {
    return String(payload ?? '').replace(/\/\*[\s\S]*?\*\//g, ' ');
  },
};
export default comment2space;