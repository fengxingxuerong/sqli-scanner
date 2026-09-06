// 双重 JSON 编码：将字符串字面量进行 JSON 双重编码绕过 WAF（对标 sqlmap djson.py）
// 适用于 JSON API 后端
export const djson = {
  name: 'djson',
  description: 'JSON 双重编码字符串字面量，绕过 JSON API WAF 检测',
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
        let str = '';
        for (let j = i + 1; j < src.length; j++) {
          const c = src[j];
          if (c === "'" && src[j - 1] !== '\\') { i = j; break; }
          str += c;
        }
        // 对字符串内容做 JSON 双重编码
        const once = JSON.stringify(str);
        const twice = JSON.stringify(once);
        out += `'${twice.slice(1, -1)}'`;
      } else if (ch === '"') {
        inDouble = true;
        let str = '';
        for (let j = i + 1; j < src.length; j++) {
          const c = src[j];
          if (c === '"' && src[j - 1] !== '\\') { i = j; break; }
          str += c;
        }
        const once = JSON.stringify(str);
        const twice = JSON.stringify(once);
        out += `"${twice.slice(1, -1)}"`;
      } else {
        out += ch;
      }
    }
    return out;
  },
};
export default djson;