// ============================================================================
// yamlLite.js —— 零依赖的 YAML **子集**解析器（只为 OpenAPI/Swagger 服务）
// ============================================================================
// 为什么自己写而不是装 `yaml`：
//   ① OpenAPI 规范**绝大多数以 YAML 流通**（Swagger Editor / springdoc / FastAPI 默认导出
//      都是 YAML），而本仓 server 侧没有 YAML 依赖，为这一个入口引入依赖面不划算；
//   ② 需求面很窄：只要能吃下 OpenAPI 常用结构（嵌套 map、序列、`- key: value` 的
//      序列项、行内流式 `[a, b]` / `{a: b}`、引号标量、数字/布尔/null）。
//
// ⚠ 硬边界（这是本模块存在的理由，改动前务必读）：
//   **解析不了就如实报"解析不了"，绝不猜、绝不半解。** 半解的 YAML 会得到一个结构
//   缺字段的伪文档 ⇒ OpenAPI 展开出**错的**请求（URL 少一段、参数少一个），
//   那比直接说"请转 JSON"危险得多 —— 后者用户看得见，前者会静默少测目标。
//   故：锚点 `&` / 别名 `*` / 标签 `!!` / 块标量 `|` `>` / 合并键 `<<` / 多文档 `---`
//   一律判 unsupported 并给出原因。
// ============================================================================

/** 不支持的 YAML 构造 —— 命中即整体拒绝（返回 ok:false + 原因） */
const UNSUPPORTED = [
  { re: /(^|\s)&\S/, desc: '锚点（&anchor）' },
  { re: /(^|\s)\*[A-Za-z0-9_-]/, desc: '别名（*alias）' },
  { re: /(^|\s)!!/, desc: '显式标签（!!tag）' },
  { re: /(^|\s)<<\s*:/, desc: '合并键（<<）' },
  { re: /^[ \t]*%YAML/i, desc: 'YAML 指令（%YAML）' },
  { re: /^[ \t]*\?[ \t]/, desc: '复杂键（? key）' },
  // 块标量：`key: |` / `key: >`（可带 `|-` `>+2` 等修饰）
  { re: /:[ \t]*[|>][+-]?\d*\s*$/, desc: '块标量（| 或 >）' },
];

/**
 * @param {string} text
 * @returns {{ok: true, value: any} | {ok: false, reason: string}}
 */
export function parseYamlLite(text) {
  if (!text || typeof text !== 'string') return { ok: false, reason: '内容为空' };

  const rawLines = text.replace(/^\uFEFF/, '').split(/\r?\n/);
  const lines = [];
  for (const [n, raw] of rawLines.entries()) {
    if (/\t/.test(raw.slice(0, raw.search(/\S|$/)))) {
      return { ok: false, reason: `第 ${n + 1} 行用 TAB 缩进（YAML 不允许）` };
    }
    const stripped = stripComment(raw);
    if (!stripped.trim()) continue;
    const trimmed = stripped.trim();
    if (trimmed === '---' || trimmed === '...') {
      // 文件开头的 `---` 是合法的文档起始标记，跳过；中间的则是多文档分隔 ⇒ 不支持
      if (lines.length === 0) continue;
      return { ok: false, reason: `第 ${n + 1} 行是多文档分隔符（本解析器只处理单文档）` };
    }
    for (const u of UNSUPPORTED) {
      if (u.re.test(stripped)) return { ok: false, reason: `第 ${n + 1} 行含 ${u.desc}` };
    }
    const indent = stripped.length - stripped.trimStart().length;
    lines.push({ indent, text: stripped.trim() });
  }
  if (!lines.length) return { ok: false, reason: '没有可解析的内容行' };

  const node = parseNode(lines, 0, lines[0].indent);
  if (!node) return { ok: false, reason: '结构解析失败（缩进不连续？）' };
  return { ok: true, value: node.value };
}

/** 剥行尾注释（引号内的 `#` 不是注释 —— URL fragment 很常见） */
function stripComment(line) {
  let quote = null;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (quote) {
      if (c === '\\') { i++; continue; }
      if (c === quote) quote = null;
      continue;
    }
    if (c === '"' || c === "'") { quote = c; continue; }
    if (c === '#' && (i === 0 || /[\s]/.test(line[i - 1]))) return line.slice(0, i).replace(/\s+$/, '');
  }
  return line.replace(/\s+$/, '');
}

const isSeq = (l) => l.text === '-' || l.text.startsWith('- ');

/** 找「顶层」的 `: ` 分隔点（引号内、行内流式 [] {} 内的冒号不算） */
function keySplit(text) {
  let quote = null;
  let depth = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (quote) {
      if (c === '\\') { i++; continue; }
      if (c === quote) quote = null;
      continue;
    }
    if (c === '"' || c === "'") { quote = c; continue; }
    if (c === '[' || c === '{') { depth++; continue; }
    if (c === ']' || c === '}') { depth--; continue; }
    if (c === ':' && depth === 0) {
      if (i + 1 === text.length) return { key: text.slice(0, i), rest: '' };
      if (text[i + 1] === ' ') return { key: text.slice(0, i), rest: text.slice(i + 2) };
    }
  }
  return null;
}

/**
 * 从 lines[i] 起解析一个节点（该行的缩进 === baseIndent）。
 * @returns {{value: any, next: number} | null}
 */
function parseNode(lines, i, baseIndent) {
  const line = lines[i];
  if (!line || line.indent < baseIndent) return null;
  if (isSeq(line)) return parseSeq(lines, i, baseIndent);
  if (keySplit(line.text)) return parseMap(lines, i, baseIndent);
  return { value: scalar(line.text), next: i + 1 };
}

function parseMap(lines, i, baseIndent) {
  const out = {};
  let cur = i;
  while (cur < lines.length) {
    const line = lines[cur];
    if (line.indent < baseIndent) break;
    if (line.indent > baseIndent) return null; // 缩进跳变 = 结构异常
    const sp = keySplit(line.text);
    if (!sp) return null;
    const key = unquote(String(sp.key).trim());
    if (sp.rest === '') {
      // 值在下面（缩进行）或为空
      const nxt = lines[cur + 1];
      if (nxt && nxt.indent > baseIndent) {
        const child = parseNode(lines, cur + 1, nxt.indent);
        if (!child) return null;
        out[key] = child.value;
        cur = child.next;
      } else {
        out[key] = null;
        cur += 1;
      }
    } else {
      out[key] = scalar(sp.rest);
      cur += 1;
    }
  }
  return { value: out, next: cur };
}

function parseSeq(lines, i, baseIndent) {
  const out = [];
  let cur = i;
  while (cur < lines.length) {
    const line = lines[cur];
    if (line.indent < baseIndent) break;
    if (line.indent > baseIndent) return null;
    if (!isSeq(line)) break;
    // 序列项内容：去掉 `- `；它的"逻辑缩进"是 `-` 之后那一列
    const content = line.text === '-' ? '' : line.text.slice(2);
    const itemIndent = baseIndent + 2;
    if (content === '') {
      const nxt = lines[cur + 1];
      if (nxt && nxt.indent > baseIndent) {
        const child = parseNode(lines, cur + 1, nxt.indent);
        if (!child) return null;
        out.push(child.value);
        cur = child.next;
      } else {
        out.push(null);
        cur += 1;
      }
    } else {
      // 把 `- key: value` 这类"行内起始的块"改写成：内容行 + 后续属于本项的更深行
      const sub = [{ indent: itemIndent, text: content }];
      let k = cur + 1;
      for (; k < lines.length && lines[k].indent > baseIndent; k++) sub.push(lines[k]);
      const child = parseNode(sub, 0, itemIndent);
      if (!child) return null;
      out.push(child.value);
      cur = k;
    }
  }
  return { value: out, next: cur };
}

function unquote(s) {
  if (s.length >= 2 && ((s[0] === '"' && s[s.length - 1] === '"') || (s[0] === "'" && s[s.length - 1] === "'"))) {
    return s.slice(1, -1).replace(/\\(["\\])/g, '$1');
  }
  return s;
}

/** 标量：流式集合 → 数组/对象；否则按引号 / 布尔 / null / 数字 / 字符串 */
function scalar(raw) {
  const s = String(raw).trim();
  if (s.startsWith('[') && s.endsWith(']')) {
    const inner = s.slice(1, -1).trim();
    return inner ? inner.split(',').map((x) => scalar(x)) : [];
  }
  if (s.startsWith('{') && s.endsWith('}')) {
    const inner = s.slice(1, -1).trim();
    const o = {};
    if (inner) {
      for (const part of inner.split(',')) {
        const sp = keySplit(part.trim());
        if (sp) o[unquote(String(sp.key).trim())] = scalar(sp.rest);
      }
    }
    return o;
  }
  if (s.length >= 2 && ((s[0] === '"' && s[s.length - 1] === '"') || (s[0] === "'" && s[s.length - 1] === "'"))) {
    return s.slice(1, -1).replace(/\\(["\\])/g, '$1');
  }
  if (s === '' || s === '~' || s === 'null' || s === 'Null' || s === 'NULL') return null;
  if (s === 'true' || s === 'True' || s === 'TRUE') return true;
  if (s === 'false' || s === 'False' || s === 'FALSE') return false;
  if (/^-?\d+$/.test(s)) return Number(s);
  if (/^-?\d*\.\d+$/.test(s)) return Number(s);
  return s;
}

export default { parseYamlLite };
