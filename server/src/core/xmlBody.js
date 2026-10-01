// ============================================================================
// core/xmlBody.js —— XML / SOAP body 注入点通道（对标 ghauri 的 XML·SOAP 支持）
// ============================================================================
// 为什么需要：JSON API 早就有嵌套叶子通道（jsonBody + _discoverJsonLeaves），
// 但**同类的 XML 形态完全空白** —— 政企/金融的老接口（SOAP 1.1/1.2、XML-RPC、各类
// `Content-Type: application/xml` 的内部网关）仍然大量存在，body 是 XML 时本扫描器
// 此前只能把整份 XML 当一个 body 参数（或根本不识别）⇒ 注入值从未进 SQL ⇒ 静默 0 检出。
// ghauri 的卖点之一就是「JSON / SOAP / XML 参数都能打」，本模块是同一能力的补齐。
//
// 设计取向（保守优先，与 jsonBody 通道同口径）：
//   · **零第三方依赖**：自写极简解析器，只认「元素 + 文本」这一种形态；
//   · **认不出的构造直接放弃**（返回 ok:false），绝不猜 —— 猜错的代价是发出畸形报文，
//     目标解析失败后整轮扫描判「不可注入」，比"没发现注入点"更糟（后者至少诚实）；
//   · 不支持注释 / CDATA / DOCTYPE / 处理指令 / 实体扩展（遇到即放弃）；
//   · 属性不做为注入点（SOAP 参数几乎都在元素文本里；属性注入面留待真需求时再开）。
//
// 往返保真：解析时解码 XML 实体（&amp; &lt; &gt; &quot; &apos; &#NN;），序列化时转义回去。
// 注入值同样走转义 —— 注入串里含 `'` `&` `<` 是常态，不转义会发出坏报文。
// ============================================================================

/** 单节点上限（防恶意深嵌套 DoS，与 jsonBody 的 50 点/6 层同数量级思路） */
const MAX_NODES = 500;
/** 深度上限 */
const MAX_DEPTH = 12;

/**
 * @typedef {object} XmlNode
 * @property {string} tag 标签名（含命名空间前缀，如 `soap:Envelope`）
 * @property {string} attrs 开标签内的属性原文（含前导空格；无属性为空串）
 * @property {boolean} selfClosing 原文是否为自闭合标签（`<tag/>`）
 * @property {Array<XmlNode|string>} children 子节点：元素节点或文本片段
 */

const ENTITIES = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'" };

/** 解码 XML 实体（只认预定义五种 + 十进制字符引用；其余原样保留 —— 不猜） */
function decodeEntities(text) {
  return String(text).replace(/&(#\d+|#x[0-9a-fA-F]+|amp|lt|gt|quot|apos);/g, (m, body) => {
    if (body[0] === '#') {
      const code = body[1] === 'x' || body[1] === 'X' ? parseInt(body.slice(2), 16) : parseInt(body.slice(1), 10);
      return Number.isFinite(code) && code > 0 && code <= 0x10ffff ? String.fromCodePoint(code) : m;
    }
    return ENTITIES[body] ?? m;
  });
}

/** 序列化时转义文本（& 必须先转，否则二次转义） */
export function escapeXmlText(text) {
  return String(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

/**
 * 解析 XML 文本为可序列化树。
 * @param {string} text XML 原文
 * @returns {{ ok: true, tree: XmlNode } | { ok: false, reason: string }}
 */
export function parseXmlBody(text) {
  const raw = typeof text === 'string' ? text : '';
  // XML 声明（`<?xml version="1.0" encoding="UTF-8"?>`）是**每条真实 SOAP 报文都有**的前缀，
  // 先剥掉它再判不支持构造 —— 否则本通道在真实目标上 100% 放弃，等于没做。
  // 只剥开头声明：正文里的处理指令（<?php…?> 等）仍走放弃分支。
  const src = raw.replace(/^\s*<\?xml\s[^>]*\?>\s*/, '');
  if (!src.trim()) return { ok: false, reason: 'empty' };
  // 保守：出现注释 / CDATA / DOCTYPE / 处理指令一律放弃（本模块不支持这些形态）
  if (/<!--|<!\[CDATA\[|<!DOCTYPE|<\?/.test(src)) {
    return { ok: false, reason: 'unsupported-construct' };
  }
  const tagRe = /<(\/)?([A-Za-z_][\w.:-]*)((?:\s+[\w.:-]+\s*=\s*(?:"[^"]*"|'[^']*'))*)\s*(\/)?>/g;
  const root = /** @type {any} */ ({ tag: '#root', attrs: '', selfClosing: false, children: [] });
  const stack = [root];
  let nodes = 0;
  let last = 0;
  let m;
  while ((m = tagRe.exec(src)) !== null) {
    const textChunk = src.slice(last, m.index);
    if (textChunk.trim()) stack[stack.length - 1].children.push(decodeEntities(textChunk));
    last = m.index + m[0].length;
    const closing = m[1] === '/';
    const tag = m[2];
    if (closing) {
      if (stack.length <= 1) return { ok: false, reason: 'unmatched-close' };
      const top = stack[stack.length - 1];
      if (top.tag !== tag) return { ok: false, reason: 'mismatched-close' };
      stack.pop();
      continue;
    }
    if (stack.length > MAX_DEPTH) return { ok: false, reason: 'too-deep' };
    if (++nodes > MAX_NODES) return { ok: false, reason: 'too-many-nodes' };
    const node = /** @type {any} */ ({ tag, attrs: m[3] || '', selfClosing: m[4] === '/', children: [] });
    stack[stack.length - 1].children.push(node);
    if (!node.selfClosing) stack.push(node);
  }
  const tail = src.slice(last);
  if (tail.trim()) return { ok: false, reason: 'trailing-text' };
  if (stack.length !== 1) return { ok: false, reason: 'unclosed' };
  const kids = root.children.filter((n) => typeof n === 'object');
  if (kids.length !== 1) return { ok: false, reason: kids.length === 0 ? 'no-root' : 'multiple-root' };
  return { ok: true, tree: /** @type {XmlNode} */ (kids[0]) };
}

/** 元素节点的文本（拼接全部直接文本子节点）；非叶子也返回拼接值，调用方按需判断 */
export function xmlNodeText(node) {
  if (node == null || typeof node !== 'object') return '';
  return node.children.filter((c) => typeof c === 'string').join('');
}

/** 是否为叶子节点（没有子元素；可以有文本） */
function isLeaf(node) {
  return !node.children.some((c) => typeof c === 'object');
}

/**
 * 收集叶子路径（点路径，与 jsonBody 通道的点路径同形态）。
 * 同名兄弟 > 1 时追加数字下标段（与 JSON 数组下标同语义），保证 setXmlLeaf 能唯一定位。
 * @param {XmlNode} tree
 * @returns {string[]} 如 `['soap:Envelope.soap:Body.GetUser.id']`
 */
export function xmlLeafPaths(tree) {
  const out = [];
  const walk = (node, path) => {
    if (out.length >= 50 || path.length > MAX_DEPTH) return;
    if (isLeaf(node)) {
      if (xmlNodeText(node) !== '' || node.selfClosing) out.push(path.join('.'));
      return;
    }
    const kids = node.children.filter((c) => typeof c === 'object');
    const counts = new Map();
    for (const k of kids) counts.set(k.tag, (counts.get(k.tag) || 0) + 1);
    const seen = new Map();
    for (const k of kids) {
      const multi = (counts.get(k.tag) || 0) > 1;
      const idx = seen.get(k.tag) ?? 0;
      seen.set(k.tag, idx + 1);
      walk(k, multi ? [...path, k.tag, String(idx)] : [...path, k.tag]);
    }
  };
  walk(tree, [tree.tag]);
  return out;
}

/**
 * 按点路径定位节点（内部用）。数字段 = 同名兄弟下标。
 * @param {XmlNode} tree
 * @param {string[]} segs
 * @returns {XmlNode|null}
 */
function resolveNode(tree, segs) {
  // 路径首段是根节点自身（与 xmlLeafPaths 的 [tree.tag] 起点互逆），不是根的子节点
  if (!segs.length || segs[0] !== tree.tag) return null;
  let cur = tree;
  for (let i = 1; i < segs.length; i++) {
    const seg = segs[i];
    if (/^\d+$/.test(seg)) continue; // 下标段由上一段消费
    const kids = /** @type {XmlNode[]} */ (
      cur.children.filter((c) => typeof c === 'object' && /** @type {XmlNode} */ (c).tag === seg)
    );
    if (!kids.length) return null;
    const next = segs[i + 1];
    let pick;
    if (/^\d+$/.test(next ?? '')) {
      pick = kids[Number(next)];
      i++; // 下标段已消费
    } else pick = kids[0];
    if (!pick) return null;
    cur = pick;
  }
  return cur;
}

/** 读取叶子文本
 * @param {XmlNode} tree @param {string} path @returns {string|null} 路径不存在返回 null
 */
export function getXmlLeaf(tree, path) {
  const node = resolveNode(tree, String(path).split('.'));
  return node ? xmlNodeText(node) : null;
}

/**
 * 把叶子文本替换为注入值。
 * @param {XmlNode} tree 会被**就地修改**，调用方负责先克隆
 * @param {string} path 点路径
 * @param {string} value 注入值（原文，序列化时统一转义）
 * @returns {boolean} 是否命中
 */
export function setXmlLeaf(tree, path, value) {
  const node = resolveNode(tree, String(path).split('.'));
  if (!node) return false;
  // 保留非文本子节点（叶子按定义没有元素子节点，此过滤只是防御）
  node.children = node.children.filter((c) => typeof c !== 'string');
  node.children.unshift(String(value));
  node.selfClosing = false; // 注入后必然有内容
  return true;
}

/** 深拷贝（结构化克隆足以：树里只有对象/数组/字符串） */
export function cloneXmlTree(tree) {
  return JSON.parse(JSON.stringify(tree));
}

/**
 * 序列化回 XML 文本。
 * @param {XmlNode} tree
 * @returns {string}
 */
export function serializeXml(tree) {
  const render = (node) => {
    if (typeof node === 'string') return escapeXmlText(node);
    const open = `<${node.tag}${node.attrs}${node.selfClosing ? '/' : ''}>`;
    if (node.selfClosing) return open;
    const inner = node.children.map(render).join('');
    return `${open}${inner}</${node.tag}>`;
  };
  return render(tree);
}

/** 是否为「应该走 XML 通道」的 Content-Type（SOAP 1.1 的 text/xml 也算） */
export function isXmlContentType(ct) {
  return typeof ct === 'string' && /(?:^|\/)(?:xml|soap\+xml)(?:;|$)/i.test(ct.trim());
}

export default {
  parseXmlBody,
  xmlLeafPaths,
  getXmlLeaf,
  setXmlLeaf,
  cloneXmlTree,
  serializeXml,
  escapeXmlText,
  isXmlContentType,
};
