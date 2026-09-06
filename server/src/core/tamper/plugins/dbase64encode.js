// Base64 编码（DEC2B64 变体）：将字符串字面量编码为 base64 后嵌入 TO_BASE64 调用
// 对标 sqlmap dbase64encode.py，与 base64encode（整体 base64）不同，仅编码字符串字面量
export const dbase64encode = {
  name: 'dbase64encode',
  description: '将字符串字面量用 TO_BASE64() 包装，绕过 WAF 字符串检测',
  transform(payload, ctx) {
    const src = String(payload ?? '');
    let out = '';
    let inSingle = false, inDouble = false;
    for (let i = 0; i < src.length; i++) {
      const ch = src[i];
      const prev = src[i - 1];
      if (inSingle) {
        if (ch === "'" && prev !== '\\') { inSingle = false; out += ch; }
        else out += ch;
        continue;
      }
      if (inDouble) {
        if (ch === '"' && prev !== '\\') { inDouble = false; out += ch; }
        else out += ch;
        continue;
      }
      if (ch === "'") {
        inSingle = true;
        // 收集单引号字符串内容
        let str = '';
        for (let j = i + 1; j < src.length; j++) {
          const c = src[j];
          if (c === "'" && src[j - 1] !== '\\') { i = j; break; }
          str += c;
        }
        out += `TO_BASE64('${Buffer.from(str).toString('base64')}')`;
      } else if (ch === '"') {
        inDouble = true;
        let str = '';
        for (let j = i + 1; j < src.length; j++) {
          const c = src[j];
          if (c === '"' && src[j - 1] !== '\\') { i = j; break; }
          str += c;
        }
        out += `TO_BASE64('${Buffer.from(str).toString('base64')}')`;
      } else {
        out += ch;
      }
    }
    return out;
  },
};
export default dbase64encode;