#!/usr/bin/env node
/**
 * set-repo-metadata.mjs —— 补齐 GitHub 仓库的**可发现性元数据**。
 *
 * 背景（2026-10-03 竞品对标时发现，本会话写接口被安全网关拦截故未执行）：
 *   本仓 `description: null` / `topics: []` / `homepage: null`。
 *   GitHub 搜索排序里 description 与 topics 是**最上游**的入口 —— 元数据为空意味着
 *   连第一屏都进不去，比「README 是中文」更早地把潜在用户滤掉。
 *   对照：sqlmap 的 topic 面（sql-injection / pentesting / database / ...）是它被发现的主要来源之一。
 *
 * 用法：
 *   export GH_TOKEN=$(printf 'protocol=https\nhost=github.com\n\n' \
 *     | "/c/Program Files/Git/mingw64/bin/git-credential-manager.exe" get \
 *     | sed -n 's/^password=//p')          # 凭据只在内存/本会话环境里，不落盘
 *
 *   node scripts/set-repo-metadata.mjs                       # dry-run（默认，只打印将要写什么）
 *   node scripts/set-repo-metadata.mjs --apply               # 真写 description + topics
 *   node scripts/set-repo-metadata.mjs --apply --release v1.1.0
 *                                                            # 额外基于已有 tag 发首个 Release
 *
 * 设计纪律（与 push-via-api.mjs 同）：
 *   - 幂等：重复运行结果一致，可安全重试。
 *   - 默认 dry-run —— **外部可见的写操作必须显式 --apply**，不做「跑一下就发布」。
 *   - 走 env 的 https_proxy（本机宿主的代理端口每次会话都变，写死必然失效）。
 *   - 校验看**读回来的值**，不看写请求的 200（"自报成功 ≠ 真的生效"）。
 */

import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const APPLY = process.argv.includes('--apply');
const relIdx = process.argv.indexOf('--release');
const RELEASE_TAG = relIdx >= 0 ? process.argv[relIdx + 1] : null;

// ── 内容：仓库门面（改这里 = 改 GitHub 上显示什么） ─────────────────────────
/**
 * 门面里的三个数字**从 README.md 派生，不手写**。
 * 理由：GitHub 远端元数据**没有任何门禁能查**，手写就等于新增一个永久无人校验的声明点。
 * README.md 是这三个数字的对外唯一真值源，且它自己由 `npm run readme:check`
 * （功能表 ↔ 代码单一取数源的双向核对）钉住 —— 派生自它即可保证永不过期。
 * 抽不到 ⇒ **拒绝写入**（fail-closed）：宁可不出描述，也不出一个过期描述。
 */
function deriveNumbers() {
  const md = readFileSync(resolve(ROOT, 'README.md'), 'utf8');
  const pick = (re, label) => {
    const m = md.match(re);
    if (!m) {
      console.error(`✗ README.md 里抽不到「${label}」的数字 —— 措辞可能已改，拒绝写过期描述。`);
      console.error('  请先核对 README.md 功能表里的那一行，同步本脚本的正则。');
      process.exit(1);
    }
    return Number(m[1]);
  };
  return {
    techniques: pick(/^\|\s*\*\*(\d+)\s*种检测技术\*\*/m, 'N 种检测技术'),
    dialects: pick(/^\|\s*\*\*(\d+)\s*种数据库\*\*/m, 'N 种数据库'),
    // 分层的「已验证」档也必须派生：光写 18 会被读成「18 种都验证过」，
    // 而 README 是 6 真机 + 3 部分通道 + 9 模板 —— 门面数字与 README 必须同口径。
    verified: pick(/\*\*(\d+)\s*种真实引擎全链路验证/m, 'N 种真实引擎全链路验证'),
    tampers: pick(/^\|\s*\*\*(\d+)\s*个 tamper 插件\*\*/m, 'N 个 tamper 插件'),
  };
}
const N = deriveNumbers();
const DESCRIPTION =
  'Web UI + CLI + desktop SQL injection scanner with CI-ready delivery reports ' +
  `(SARIF / CVSS / CWE). ${N.techniques} techniques - ${N.dialects} dialects ` +
  `(${N.verified} engine-verified) - ${N.tampers} tamper plugins.`;

// 20 个上限（GitHub 硬限制）。挑选原则：与 sqlmap / nuclei 的话题面重叠、
// 且**不得误导** —— 不写 `bug-bounty` / `exploit` 这类与产品定位不符的流量词。
const TOPICS = [
  'sql-injection', 'sqli', 'sql-injection-scanner', 'vulnerability-scanner',
  'security-tools', 'security-testing', 'pentesting', 'penetration-testing',
  'appsec', 'webappsec', 'waf', 'waf-bypass', 'database-security',
  'devsecops', 'ci-cd', 'sarif', 'nodejs', 'express', 'react', 'tauri',
];

// ── 仓库定位 ─────────────────────────────────────────────────────────────────
const remoteUrl = execFileSync('git', ['remote', 'get-url', 'origin'], { cwd: ROOT, encoding: 'utf8' }).trim();
const m = remoteUrl.match(/github\.com[:/]([^/]+)\/([^/.]+)(?:\.git)?$/);
if (!m) { console.error(`无法从 remote URL 解析 owner/repo：${remoteUrl}`); process.exit(1); }
const [, OWNER, REPO] = m;
const API = `https://api.github.com/repos/${OWNER}/${REPO}`;
const PROXY = process.env.https_proxy || process.env.HTTPS_PROXY;
const TOKEN = process.env.GH_TOKEN || process.env.GITHUB_TOKEN;

let ProxyAgent;
try { ({ ProxyAgent } = await import('undici')); } catch { /* 无 undici 则直连 */ }
const dispatcher = ProxyAgent && PROXY ? new ProxyAgent({ uri: PROXY }) : undefined;

/** 单次请求。retries 覆盖本机代理链路偶发传输损坏（与 push-via-api 同因）。
 *  读接口（GET）公开可读 —— 无 token 也放行，这样 dry-run 不依赖凭据。 */
async function api(method, url, body, { retries = 4 } = {}) {
  let lastErr;
  for (let i = 1; i <= retries; i++) {
    try {
      const headers = {
        Accept: 'application/vnd.github+json',
        'User-Agent': 'set-repo-metadata',
        'X-GitHub-Api-Version': '2022-11-28',
      };
      if (TOKEN) headers.Authorization = `Bearer ${TOKEN}`;
      const res = await fetch(url, {
        method,
        headers,
        body: body ? JSON.stringify(body) : undefined,
        dispatcher,
      });
      const text = await res.text();
      if (!res.ok) throw new Error(`${method} ${url} -> ${res.status}: ${text.slice(0, 300)}`);
      return text ? JSON.parse(text) : {};
    } catch (e) {
      lastErr = e;
      const retriable = /fetch failed|UND_ERR_SOCKET|other side closed|ECONNRESET|50[0-9]|timeout|EAI_AGAIN|malformed request/i
        .test(String(e?.message || e));
      if (!retriable || i === retries) break;
      await new Promise((r) => setTimeout(r, Math.min(1500 * i, 6000)));
    }
  }
  throw lastErr;
}

/** 从 CHANGELOG.md 抽 `## [<tag>]` 到下一个 `## [` 之间的小节，作为 Release 正文。
 *  兼容两种写法：tag `v1.1.0` ↔ CHANGELOG 里的 `## [1.1.0]`（本仓 CHANGELOG 不带 `v` 前缀，
 *  而 git tag 带 —— 实测踩过：只按原样匹配会抽不到，静默退化成最短正文）。 */
function changelogSection(tag) {
  const md = readFileSync(resolve(ROOT, 'CHANGELOG.md'), 'utf8');
  const candidates = [tag, tag.replace(/^v/, '')];
  let start = -1;
  for (const c of candidates) {
    start = md.indexOf(`## [${c}]`);
    if (start >= 0) break;
  }
  if (start < 0) return null;
  const rest = md.slice(start + 1);
  const nextIdx = rest.indexOf('\n## [');
  const body = (nextIdx < 0 ? rest : rest.slice(0, nextIdx)).trim();
  return body.length > 20 ? body : null;
}

// ── 主流程 ───────────────────────────────────────────────────────────────────
if (APPLY && !TOKEN) {
  console.error('--apply 需要 GH_TOKEN / GITHUB_TOKEN 环境变量。取 token 的姿势见本文件顶部注释。');
  process.exit(1);
}

console.log(`仓库：${OWNER}/${REPO}`);
console.log(`模式：${APPLY ? 'APPLY（真写）' : 'DRY-RUN（不写；加 --apply 才生效）'}`);
console.log(`代理：${PROXY ? PROXY : '（直连）'}`);

const before = await api('GET', API);
console.log('\n--- 当前值 ---');
console.log(`description: ${JSON.stringify(before.description)}`);
console.log(`topics     : ${JSON.stringify(before.topics ?? [])}`);
console.log(`homepage   : ${JSON.stringify(before.homepage)}`);

console.log('\n--- 目标值 ---');
console.log(`description: ${JSON.stringify(DESCRIPTION)}  (${DESCRIPTION.length} 字符)`);
console.log(`topics     : ${TOPICS.length} 个 → ${TOPICS.join(', ')}`);
if (RELEASE_TAG) {
  const sec = changelogSection(RELEASE_TAG);
  console.log(`release    : ${RELEASE_TAG}（正文 ${sec ? `${sec.length} 字符，取自 CHANGELOG.md` : '⚠ 未在 CHANGELOG.md 找到该 tag 的小节，将用最短正文'}）`);
}

if (!APPLY) {
  console.log('\n[DRY-RUN] 未写入。确认无误后加 --apply 重跑。');
  process.exit(0);
}

console.log('\n--- 写入 ---');
await api('PATCH', API, { description: DESCRIPTION, homepage: '' });
console.log('✓ description 已提交');

const topicsRes = await api('PUT', `${API}/topics`, { names: TOPICS });
console.log(`✓ topics 已提交（回显 ${topicsRes.names?.length ?? 0} 个）`);

if (RELEASE_TAG) {
  const sec = changelogSection(RELEASE_TAG);
  const existing = await api('GET', `${API}/releases/tags/${RELEASE_TAG}`).catch(() => null);
  if (existing?.id) {
    console.log(`→ Release ${RELEASE_TAG} 已存在（id=${existing.id}），跳过创建`);
  } else {
    const rel = await api('POST', `${API}/releases`, {
      tag_name: RELEASE_TAG,
      name: RELEASE_TAG,
      body: sec || `见 [CHANGELOG.md](CHANGELOG.md) 的 ${RELEASE_TAG} 小节。`,
      draft: false,
      prerelease: false,
    });
    console.log(`✓ Release 已创建：${rel.html_url}`);
  }
}

// ── 校验：读回来看真值，不采信上面的 200 ────────────────────────────────────
console.log('\n--- 校验（读回远端真值） ---');
const after = await api('GET', API);
const afterTopics = await api('GET', `${API}/topics`);
const descOk = after.description === DESCRIPTION;
const topicsOk = afterTopics.names?.length === TOPICS.length
  && TOPICS.every((t) => afterTopics.names.includes(t));

console.log(`${descOk ? '✓' : '✗'} description = ${JSON.stringify(after.description)}`);
console.log(`${topicsOk ? '✓' : '✗'} topics = ${afterTopics.names?.length ?? 0} 个`);
if (!descOk || !topicsOk) {
  console.error('\n元数据未完全生效 —— 可能是组织策略或权限不足，请核对 GitHub 页面实际显示。');
  process.exit(1);
}
console.log('\n全部生效。');
