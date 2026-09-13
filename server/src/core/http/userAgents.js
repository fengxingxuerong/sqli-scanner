// ============================================================================
// userAgents.js —— 内置 User-Agent 池与随机选取（WAF 规避 / 随机指纹）
//
// 从 httpClient.js 抽离，[阶段② 拆上帝对象 2026-09-13]。零外部依赖，纯数据 + 纯函数。
// ============================================================================

// 内置常见浏览器 User-Agent 池（原逻辑不变）
const DESKTOP_UA_POOL = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0',
  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
  'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0',
];

// 移动端 UA 池（对标 sqlmap --mobile：CLI 将 --mobile 映射为 wafEvasion.randomUA='mobile'）
const MOBILE_UA_POOL = [
  'Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1',
  'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36',
  'Mozilla/5.0 (iPad; CPU OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1',
];

const UA_POOL = [...DESKTOP_UA_POOL, ...MOBILE_UA_POOL];

/**
 * 从 UA 池随机选取 User-Agent 字符串（WAF 规避 / 随机指纹）。
 * @param {'mobile'|'desktop'|undefined} kind 指定 'mobile' 则仅从移动端池取，否则从全池取
 * @returns {string} User-Agent 字符串
 */
export function pickRandomUA(kind) {
  const pool = kind === 'mobile' ? MOBILE_UA_POOL : UA_POOL;
  return pool[Math.floor(Math.random() * pool.length)];
}
