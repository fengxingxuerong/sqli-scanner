// 每个字符前置 %（类名 percentage，对齐 sqlmap 官方语义，仅 ASP 目标有效）
// 例：SELECT -> %S%E%L%E%C%T；空格不处理；已编码 %XX 原样保留。
// [P0-FIX 2026-09-05] 原实现仅在关键字字符"之间"插 %（SELECT -> S%E%L%E%C%T），
// 缺首字符前导 %，与官方 doctest 不符。
// 官方参考：sqlmap/tamper/percentage.py：
//   >>> tamper('SELECT FIELD FROM TABLE')
//   '%S%E%L%E%C%T %F%I%E%L%D %F%R%O%M %T%A%B%L%E'
//   （空格原样保留；%XX 序列透传；其余每字符前置 %）
export const percentage = {
  name: 'percentage',
  description: '每个字符前置 %（空格与已编码 %XX 保留），仅 ASP 目标有效，绕过弱 WAF',
  dbms: ['SQL Server'], // [P1-FIX] 方言限定：异构库下无效，运行时告警
  transform(payload) {
    if (typeof payload !== 'string' || payload.length === 0) return payload;
    let out = '';
    for (let i = 0; i < payload.length; i++) {
      if (payload[i] === '%' && /^[0-9A-Fa-f]{2}$/.test(payload.slice(i + 1, i + 3))) {
        out += payload.slice(i, i + 3); // 已编码序列，透传
        i += 2;
      } else if (payload[i] === ' ') {
        out += payload[i]; // 空格原样保留（官方行为）
      } else {
        out += '%' + payload[i];
      }
    }
    return out;
  },
};

export default percentage;
