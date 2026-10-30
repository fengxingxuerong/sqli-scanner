// ============================================================================
// reproPack.js —— 可复现件生成：`repro.sh` + `expect.json`（D177）
//
// 为什么要有这一层：报告里的 PoC 是「一条能跑的请求」，但**没人知道它是不是稳定**——
// 会话失效、被 WAF 拦、目标抖动都会让同一条请求第二次就变样。竞品把「可执行 PoC」当卖点
// （VulnHunter：proves them with executable PoCs，见 docs/竞品对标-2026W44.md §一/A），
// 本仓的证据链（poc.curl/poc.raw）已经很强，缺的是**判定「两次重放是否一致」的判据**。
//
// 三条纪律：
//   1. 只判定「同一请求重放 N 次结果是否一致」，**不宣称漏洞仍存在**（那是另一回事）；
//   2. 归一化口径由引擎与 shell 脚本共用同一个定义（status + body sha256），否则
//      「脚本说一致、引擎说不一致」又是一种自相矛盾；
//   3. 生成的脚本必须能直接跑：路径/URL/body 里的引号要转义，不能拼出注入。
// ============================================================================
import { createHash } from 'node:crypto';

/**
 * @typedef {object} Sample 一次重放的归一化结果
 * @property {number} status HTTP 状态码
 * @property {number} len 响应体字节数（原始长度，便于排查）
 * @property {number} stableLen 剔除易变标记后的字节数
 * @property {string} hash 剔除易变标记后响应体的 sha256（前 16 位，够比对）
 */

/**
 * 易变内容剔除：只去掉**明显的机器时间标记**（10 位以上数字串、ISO-8601 时间戳）。
 * 为什么需要：`"reproduced"` 的判据是「两次响应一致」，而真实页面常带
 * `<!-- generated at 1793002213 -->` 这类每秒都变的时间戳——不剔除的话，一个稳定的
 * 命中会在跨秒重放时被判成「单次命中」（假警报）。剔除清单刻意保持**极小且可解释**：
 * 不做相似度、不做模糊匹配，剥完仍是严格字节比较。
 * ⚠ 与 `buildReproScript` 里的 sed 保持同一口径（`[0-9]{10,}`、ISO 时间戳）。
 * @param {string} text 原始响应体
 * @returns {string} 剥掉易变标记后的文本
 */
function stripVolatile(text) {
  return String(text ?? '')
    .replace(/\d{10,}/g, '')
    .replace(/\d{4}-\d{2}-\d{2}T[\d:.]+Z?/g, '');
}

/**
 * 响应归一化：只留「同一请求重放应当稳定」的部分（状态码 + 剔除易变标记后的响应体哈希）。
 * 刻意不含 Date 头/耗时/响应头顺序——那些天然抖动。响应体字段兼容两种形态：
 * 引擎 httpClient 返回 axios 风格 `data`，测试/其它通道可能给 `body`。
 * （首版只读 `body`，真实重放拿到空串 ⇒ 哈希恒定、判定退化成只看状态码，是假绿，已修。）
 * @param {{status?: number, data?: string|Buffer, body?: string|Buffer}} res 响应
 * @returns {Sample} 归一化样本
 */
export function normalizeForCompare(res) {
  const raw = res?.body ?? res?.data ?? '';
  const body = Buffer.isBuffer(raw) ? raw : Buffer.from(String(raw ?? ''));
  const stable = Buffer.from(stripVolatile(body.toString('utf8')), 'utf8');
  return {
    status: Number(res?.status) || 0,
    len: body.length,
    stableLen: stable.length,
    hash: createHash('sha256').update(stable).digest('hex').slice(0, 16),
  };
}

/**
 * 两个归一化样本是否一致。
 * @param {Sample} a 样本 A
 * @param {Sample} b 样本 B
 * @returns {boolean} 状态码与响应体哈希都相同才算一致
 */
export function sameSample(a, b) {
  return a.status === b.status && a.hash === b.hash;
}

/**
 * POSIX shell 单引号转义：任何字符都能安全塞进 `'...'`。
 * @param {unknown} s 原始文本
 * @returns {string} 可放进单引号的安全形态（含两侧引号）
 */
export function shq(s) {
  return `'${String(s ?? '').replace(/'/g, `'\\''`)}'`;
}

/**
 * 生成可复现脚本（bash）：重放同一请求 N 次，响应一致才 exit 0。
 * @param {object} vuln 漏洞条目（读 `poc.method/url/headers/body`）
 * @param {{repeats?: number}} [ctx] 重放次数（默认 2）
 * @returns {string} 可执行的 shell 脚本
 */
export function buildReproScript(vuln, ctx = {}) {
  const repeats = Math.max(2, Number(ctx.repeats) || 2);
  const poc = vuln?.poc || {};
  const method = String(poc.method || 'GET').toUpperCase();
  const headers = poc.headers && typeof poc.headers === 'object' ? Object.entries(poc.headers) : [];
  const headerArgs = headers.map(([k, v]) => `  -H ${shq(`${k}: ${v}`)} \\`).join('\n');
  const bodyArg = poc.body ? `  --data-raw ${shq(poc.body)} \\` : '';
  return `#!/usr/bin/env bash
# 由 sqli-scanner 生成（D177）：重放同一请求 ${repeats} 次，判定「响应是否稳定」。
# 一致 ≠ 漏洞仍存在；不一致请先排查会话失效 / 被 WAF 拦 / 目标抖动。
set -u
REPEATS=${repeats}
URL=${shq(poc.url || '')}
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
prev=''
fail=0
i=1
while [ "$i" -le "$REPEATS" ]; do
  code="$(curl -sS -o "$tmp/body.$i" -w '%{http_code}' -X ${method} \\
${headerArgs}${bodyArg}  "$URL")" || fail=1
  # 与引擎同一口径：先剔除明显的易变时间标记（10 位以上数字 / ISO 时间戳），再取哈希
  sed -E 's/[0-9]{10,}//g; s/[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z?//g' "$tmp/body.$i" > "$tmp/stable.$i"
  sum="$(sha256sum "$tmp/stable.$i" | cut -d' ' -f1 | cut -c1-16)"
  sig="$code:$sum"
  echo "run $i => status=$code body_sha256=$sum"
  if [ -n "$prev" ] && [ "$sig" != "$prev" ]; then fail=1; fi
  prev="$sig"
  i=$((i + 1))
done
if [ "$fail" -ne 0 ]; then
  echo 'INCONSISTENT：重放结果不一致（不是稳定可复现的命中）'
  exit 1
fi
echo 'CONSISTENT：同一请求重放结果一致'
exit 0
`;
}

/**
 * 生成机器可读的期望值（`expect.json`），与脚本同一口径。
 * @param {object} vuln 漏洞条目
 * @param {{repeats?: number, target?: string}} [ctx] 上下文
 * @returns {object} 期望值对象
 */
export function buildExpectJson(vuln, ctx = {}) {
  const repeats = Math.max(2, Number(ctx.repeats) || 2);
  return {
    _generatedBy: 'sqli-scanner D177 repro-pack',
    target: ctx.target || vuln?.poc?.url || '',
    param: vuln?.param || vuln?.affectedParam || '',
    technique: vuln?.technique || '',
    repeats,
    compare: ['status', 'body_sha256'],
    expect: 'consistent',
    note: '一致指「同一请求重放结果稳定」，不表示漏洞仍存在；不一致需先排查会话失效/WAF/抖动。',
  };
}

/**
 * 文件名安全化（与 fixPrompt 同一口径：参数名来自目标应用，可能含任意字符）。
 * @param {string} raw 原始片段
 * @returns {string} 安全片段
 */
export function safeReproName(raw) {
  const cleaned = String(raw || '')
    .replace(/[^a-zA-Z0-9._-]/g, '_')
    .replace(/\.{2,}/g, '_')
    .replace(/^[._]+/, '')
    .slice(0, 60);
  return cleaned || 'finding';
}
