// ============================================================================
// bin/cli/batchTargets.js —— `-m` 的目标来源：URL 列表 **或** 请求集合（对标 sqlmap 2.0
// 的「OpenAPI 目标生成」，并把本仓已有的集合解析器与批量池合流）
// ============================================================================
// 为什么要有这一层（三个既有事实凑出的一个缺口）：
//   ① `-r` 能吃集合（`core/requestCollectionParser.js`：Burp XML / HAR / Postman / OpenAPI），
//      但**只取第 1 条**，其余打一句「要逐个测请拆分文件后分别用 -r」—— 等于把
//      「接口清单」这条最省事的批量入口堵死了；
//   ② `-m` 能吃多目标，但**只认一行一个 URL 的纯文本** —— 真实的接口清单（OpenAPI/Postman/
//      HAR/Burp）全被当成非法 URL 扔掉；
//   ③ 批量池（batchPool）刚补齐并发 + 故障隔离 + 摘要点名，正缺一个「目标从哪来」的供给面。
// 竞品坐标（2026-10-02 核实）：sqlmap 2.0(WIP) 已把 **OpenAPI 目标生成**列入新能力；
// ghauri 的 `-m`(experimental) 仍只吃文本 URL、`-r` 只吃单请求，且批量**没有故障隔离**
// （一个无响应目标会拖住整队）。本模块把三者接起来：**集合 → N 个目标 → 批量池**。
//
// 硬语义（两条，改之前先想清楚）：
//   · **格式必须被点名**：识别成什么格式、展开出几个目标，一律打到 stderr。
//     静默降级是本仓反复踩的坑（「根本没测」会被读成「测了且安全」）。
//   · **OpenAPI 不是抓包**：参数值来自 example/default，缺失处是占位符。这个 caveat
//     由解析器给出，本模块**原样往上传**，不替它淡化。
// ============================================================================

import { detectRequestFormat, parseRequestCollection } from '../../src/core/requestCollectionParser.js';
import { bodyToJsonString } from './args.js';

/** 批量模式下允许的 HTTP 方法（与 `-l` 同口径：越界的回退 GET 由调用方决定） */
export const BATCH_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'];

/**
 * 把 `-m` 的文件内容展开成批量目标。
 *
 * @param {string} text 文件内容
 * @returns {{
 *   kind: 'urls'|'collection',
 *   format: string|null,
 *   items: Array<string|object>,
 *   warnings: string[],
 *   skipped: number
 * }} skipped = 集合里被过滤掉的请求数（非 http(s) / 方法越界 / 解析失败）
 */
export function expandBatchTargets(text) {
  if (!text || typeof text !== 'string') {
    return { kind: 'urls', format: null, items: [], warnings: ['文件为空'], skipped: 0 };
  }
  const format = detectRequestFormat(text);

  // —— 纯文本：保持既有「一行一个 URL」语义（唯一的向后兼容路径）——
  // 注意 'raw' 也包含「JSON 解析失败」与「单请求文本」两种形态：前者本就是坏文件，
  // 后者（整份抓包）在批量语境下的正确解读是"逐请求"，但只有一个请求 ⇒ 展开成 1 个 URL 更直观。
  // 关键约束：**不在这里静默吞掉任何一行** —— 过滤掉的行数由调用方点名。
  // [2026-10-02] `openapi-yaml` 从"按 URL 列表处理"挪进集合分支：YAML 现在能展开
  // （零依赖子集解析器），展开不了时 parseRequestCollection 会带原因的 warnings，
  // items 为空 ⇒ 调用方照样会报"批量目标为空"并退出，不存在静默降级。
  if (!format || format === 'raw' || format === 'unsupported') {
    const lines = text.split(/\r?\n/);
    const items = [];
    let skipped = 0;
    for (const raw of lines) {
      const line = raw.trim();
      if (!line || line.startsWith('#')) continue; // 注释行与空行不算"被过滤"
      if (/^https?:\/\//i.test(line)) items.push(line);
      else skipped++;
    }
    const warnings = [];
    if (format === 'unsupported') {
      warnings.push('识别为 XML 但不是 Burp 导出（<items>/<item>），已按「一行一个 URL」处理。');
    }
    if (skipped) warnings.push(`忽略 ${skipped} 行非 http(s) 内容（URL 列表模式下每行必须是一个 http(s) 地址）`);
    return { kind: 'urls', format: format || 'raw', items, warnings, skipped };
  }

  // —— 集合格式 ——
  const coll = parseRequestCollection(text);
  const items = [];
  let skipped = 0;
  let schemeRewritten = 0;
  let multipart = 0;
  let bodyUnusable = 0;
  for (const r of coll.requests || []) {
    const url = String(r?.url || '');
    // ⚠ 解析器走的是「原始报文」往返（buildRawRequest 只留 pathname+search + Host，
    //   协议在重建时丢失、parseRequestFile 默认补 http）⇒ `ftp://h/3` 出来会是
    //   `http://h/3` —— **目标被静默改了**。改成扫 http 比跳过更糟（扫的不是用户
    //   写的那个东西），故用 label 里留存的原始 URL 把这类条目挑出来跳过并点名。
    const label = typeof r?.label === 'string' ? r.label : '';
    const orig = (label.match(/\s(\S+)$/) || [])[1] || '';
    if (orig && !/^https?:\/\//i.test(orig)) { skipped++; schemeRewritten++; continue; }
    if (!/^https?:\/\//i.test(url)) { skipped++; continue; }
    const method = String(r?.method || 'GET').toUpperCase();
    if (!BATCH_METHODS.includes(method)) { skipped++; continue; }
    const headers = r.headers || {};
    const ct = String(
      headers['Content-Type'] || headers['content-type']
      || Object.entries(headers).find(([k]) => String(k).toLowerCase() === 'content-type')?.[1] || '',
    );
    // ⚠ body 的形态必须在**展开期**定死，不能留到扫描期才发现：
    //   · multipart 走 bodyToJsonString 会把整份 body 塌成一个垃圾键（本仓 `-r` 侧已栽过，
    //     TODO §O 有完整记录）⇒ 批量里一律**跳过并点名**，让用户改用 -r 单条处理；
    //   · 其它无法转成 JSON 的 body（裸 XML/未知格式）同理 —— 带着空 body 去扫一个
    //     POST 端点 = 0 注入点 = 「根本没测」，比跳过更危险。
    //   跳过而不是硬扫，是因为**扫出来的会是一个与抓包不同的目标**，那才是假阴性之源。
    let body = null;
    if (r.body) {
      if (/multipart\/form-data/i.test(ct)) { skipped++; multipart++; continue; }
      body = bodyToJsonString(r.body);
      if (!body) { skipped++; bodyUnusable++; continue; }
    }
    items.push({
      url,
      method,
      headers,
      body,
      label: r.label || `${method} ${url}`,
    });
  }
  const warnings = (coll.warnings || []).slice();
  if (skipped) warnings.push(`集合里 ${skipped} 个请求被跳过（非 http(s) URL 或方法不在 ${BATCH_METHODS.join('/')} 内）`);
  if (schemeRewritten) {
    warnings.push(
      `其中 ${schemeRewritten} 个是**非 http(s) 协议**：解析器经「原始报文」往返会把它静默补成 http，`
      + `扫出来的就不是你写的那个目标 ⇒ 一律跳过不扫（要扫请先改成 http/https 明确写出）`,
    );
  }
  if (multipart) {
    warnings.push(
      `其中 ${multipart} 个是 **multipart/form-data**：批量模式不做 JSON 化（会把整份 body 塌成一个`
      + `垃圾键，见 TODO §O），故跳过不扫 —— 这些请求请逐条用 -r 处理`,
    );
  }
  if (bodyUnusable) {
    warnings.push(
      `其中 ${bodyUnusable} 个的 body 无法转成 JSON（且非 multipart）：带着空 body 去扫一个 POST`
      + `端点会得到 0 注入点（等于没测），故跳过不扫 —— 请逐条用 -r 核对`,
    );
  }
  return { kind: 'collection', format, items, warnings, skipped };
}

/** 集合条目 → 覆盖到扫描参数上（与 `-l` 的字段映射同一口径，抽出来是为了能单测） */
export function scanArgsFromRequest(args, req) {
  const out = { ...args };
  out.url = req.url;
  out.method = BATCH_METHODS.includes(String(req.method || '').toUpperCase())
    ? String(req.method).toUpperCase()
    : 'GET';
  // ⚠️ multipart 抓包不能走 bodyToJsonString 那条启发式（会把整份 body 塌成一个垃圾键），
  // 故这里只在有 JSON body 时覆盖；multipart 由调用方按 Content-Type 另行处理。
  if (req.body) out.body = req.body;
  const headers = req.headers || {};
  const cookieKey = Object.keys(headers).find((k) => k.toLowerCase() === 'cookie');
  if (cookieKey) out.cookie = headers[cookieKey];
  const other = {};
  for (const [k, v] of Object.entries(headers)) {
    const kl = String(k).toLowerCase();
    if (kl === 'cookie' || kl === 'host' || kl === 'content-length') continue;
    other[k] = v;
  }
  if (Object.keys(other).length) out.headerObj = other;
  return out;
}

export default { expandBatchTargets, scanArgsFromRequest, BATCH_METHODS };
