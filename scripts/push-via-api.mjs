#!/usr/bin/env node
/**
 * push-via-api.mjs —— 当 `git push` 被网络阻断时，改用 GitHub Git Data API 推送。
 *
 * 背景（2026-09-22 实测，本机网络）：
 *   - `api.github.com` 走代理 = 200（可用）
 *   - `codeload` / `objects.githubusercontent.com` 走代理 = 301 / 404（可用）
 *   - `github.com` 走代理 = 000 / CONNECT tunnel failed 502
 *   - `github.com:443` 不走代理 = 000（21s 超时）
 *   → `github.com:443` 双向不通 ⇒ `git push` / `git ls-remote` 必失败，
 *     `env -u http_proxy ...`（旧招）本网络下无效。
 *
 * 原理：本仓库私有，git-over-HTTPS 走不通但 REST API 通 ⇒ 用 API 手工搬运对象。
 *
 * 核心设计（三条都是踩坑后定的，改前请先读 `docs`/记忆里的复盘）：
 *
 *   ① **唯一基准 = 远端 base**。先 `GET /git/commits/<base>` 拿它的 tree sha，
 *      再 `GET /git/trees/<tree>?recursive=1` 一次性拿到
 *        - 全部「远端已有对象」sha 集合（判断哪些 blob/tree 需要上传）
 *        - 全部「远端已有树路径 → sha」映射（作为 base_tree）
 *      ⚠️ 不要退回"沿祖先链找本地已有提交"当基准 —— 那样 remoteObjs 与
 *      remotePaths 会指向**不同的提交**，导致所有 tree 被误判为「已变更」，
 *      最终把整个仓库路径错误地挂到子目录下（实测污染 3001 条目）。
 *
 *   ② **解析 tree 一律用 `-z`**。默认模式下 git 会给非 ASCII 路径加引号 +
 *      八进制转义（实测 38 处）→ 直送 API 会生成**带字面引号的文件名**。
 *
 *   ③ **`POST /git/trees` 只传「变更条目」+ `base_tree`**。
 *      传全量条目（含大量未变更项）会被拒：`422 Invalid tree info`。
 *      最小复现已验证：`{ base_tree, tree: [仅变更项] }` → 201，
 *      且返回树 sha 与本地**完全一致**。
 *
 * 其它：
 *   - **message 尾部换行**：GitHub 建 commit 时给 message 末尾补一个 `\n`，
 *     本地 commit 的 message 已自带 → 需先 `replace(/\n+$/,'')`。
 *   - **重试**：代理下 socket 偶发 `UND_ERR_SOCKET` → 最多 6 次指数退避。
 *   - **幂等**：远端 HEAD 的 tree 已等于本地 tree 时直接退出。
 *   - **校验**：递归拉远端树与本地逐条比对 path/mode/sha（比 commit sha 更可靠）。
 *
 * 用法：
 *   export GH_TOKEN=$(printf 'protocol=https\nhost=github.com\n\n' \
 *     | "/c/Program Files/Git/mingw64/bin/git-credential-manager.exe" get \
 *     | sed -n 's/^password=//p')
 *   node scripts/push-via-api.mjs [--remote origin] [--branch master]
 *                                 [--local <sha>] [--base <sha>] [--dry-run] [--force-commit]
 *
 * 退出码：0 = 推送且校验通过；1 = 失败（含校验不通过）。
 *
 * ⚠️ 运行时注意（实测）：
 *   - 全量重建树的 API 往返较慢，**整轮约 2.5 分钟**。在带 2 分钟默认超时的
 *     非交互执行环境里必须**后台跑**（否则会被 SIGTERM 掐断在半途）。
 *   - 脚本**幂等**：被掐断后直接重跑即可 —— 远端 HEAD 的树已等于本地树时
 *     会秒退并打印"内容已同步"。
 *   - 日志落在 `.push-log.txt`；失败详情落在 `.push-via-api-result.json`。
 *     两者都在 `.gitignore` 覆盖范围内，勿提交。
 *   - `refs/remotes/origin/master` 缺失（fetch 不落 ref 的本机故障）与
 *     `ls-remote` 失败都是**预期噪音**，脚本会自动回退到读 API 取 base。
 */
import { execFileSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';

// ---------- 参数 ----------
const argv = process.argv.slice(2);
const opt = (name, def) => {
  const i = argv.indexOf(`--${name}`);
  return i >= 0 && argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[i + 1] : def;
};
const DRY = argv.includes('--dry-run');
const FORCE_COMMIT = argv.includes('--force-commit');

const git = (...a) => execFileSync('git', a, { encoding: 'utf8', maxBuffer: 1 << 28 }).trim();
const gitBuf = (...a) => execFileSync('git', a, { maxBuffer: 1 << 28 });

const REMOTE = opt('remote', 'origin');
const BRANCH = opt('branch', 'master');
const remoteUrl = git('remote', 'get-url', REMOTE);
const m = remoteUrl.match(/github\.com[:/]([^/]+)\/([^/.]+?)(?:\.git)?$/);
if (!m) { console.error(`无法从 remote URL 解析 owner/repo：${remoteUrl}`); process.exit(1); }
const [, OWNER, REPO] = m;
const API = `https://api.github.com/repos/${OWNER}/${REPO}`;
const PROXY = process.env.https_proxy || process.env.HTTPS_PROXY;

const TOKEN = process.env.GH_TOKEN || process.env.GITHUB_TOKEN;
if (!TOKEN) { console.error('缺少 GH_TOKEN / GITHUB_TOKEN 环境变量'); process.exit(1); }

let ProxyAgent;
try { ({ ProxyAgent } = await import('undici')); } catch { /* 无 undici 则直连 */ }
const dispatcher = ProxyAgent && PROXY ? new ProxyAgent({ uri: PROXY }) : undefined;

// ---------- API（带重试） ----------
async function apiOnce(method, path, body) {
  const res = await fetch(API + path, {
    method,
    headers: {
      Authorization: `Bearer ${TOKEN}`,
      Accept: 'application/vnd.github+json',
      'User-Agent': 'push-via-api',
      'X-GitHub-Api-Version': '2022-11-28',
    },
    body: body ? JSON.stringify(body) : undefined,
    dispatcher,
  });
  const text = await res.text();
  if (!res.ok) {
    if (process.env.PUSH_DEBUG && body) console.error('[DEBUG] 请求体:', JSON.stringify(body).slice(0, 1500));
    throw new Error(`${method} ${path} -> ${res.status}: ${text.slice(0, 400)}`);
  }
  return text ? JSON.parse(text) : {};
}

async function api(method, path, body) {
  for (let i = 1; i <= 6; i++) {
    try {
      return await apiOnce(method, path, body);
    } catch (e) {
      // [2026-09-23] `400 malformed request` 也要重试：实测同一 blob 内容（98562B）原样重发即 201，
      // 说明是本机代理链路上的偶发传输损坏，不是内容问题。blob 上传幂等（同内容 → 同 sha），可安全重试。
      const retriable = /fetch failed|UND_ERR_SOCKET|other side closed|ECONNRESET|50[0-9]|timeout|EAI_AGAIN|malformed request/i
        .test(String(e?.message || e));
      if (!retriable || i === 6) throw e;
      const wait = Math.min(2000 * i, 8000);
      console.log(`    ↻ 重试 ${i}/6（${String(e.message).slice(0, 60)}）等 ${wait}ms`);
      await new Promise((r) => setTimeout(r, wait));
    }
  }
}

// ---------- tree 解析（必须 -z） ----------
function listTree(treeSha) {
  const items = gitBuf('ls-tree', '-z', treeSha).toString('utf8').split('\0').filter(Boolean);
  return items.map((raw) => {
    const mm = raw.match(/^(\d+)\s+(\w+)\s+([0-9a-f]{40})\t([\s\S]*)$/);
    if (!mm) throw new Error(`无法解析 tree 条目: ${JSON.stringify(raw.slice(0, 120))}`);
    return { mode: mm[1], type: mm[2], sha: mm[3], name: mm[4] };
  });
}

// ---------- 主流程 ----------
console.log(`仓库 ${OWNER}/${REPO}  分支 ${BRANCH}`);
const localSha = opt('local', git('rev-parse', BRANCH));
const rootTree = git('rev-parse', `${localSha}^{tree}`);

// 远端 base
let base = opt('base', '');
if (!base) {
  try { base = git('rev-parse', `refs/remotes/${REMOTE}/${BRANCH}`); } catch { /* 继续 */ }
}
if (!base) {
  try {
    const out = git('ls-remote', REMOTE, `refs/heads/${BRANCH}`);
    base = (out.split(/\s+/)[0] || '').trim();
  } catch { /* 继续（本网络通常不通） */ }
}
if (!base) {
  try { base = (await api('GET', `/git/refs/heads/${BRANCH}`)).object.sha; } catch (e) {
    console.error(`取远端 ${BRANCH} 失败（可能是空库）：${e.message}`);
    process.exit(1);
  }
}
if (!/^[0-9a-f]{40}$/.test(base)) { console.error(`base 非法：${base}`); process.exit(1); }

console.log(`本地 ${localSha}  tree ${rootTree}`);
console.log(`远端 ${base}`);

if (base === localSha) { console.log('✅ 已是最新，无需推送'); process.exit(0); }

// 远端 base 的真实 tree sha（注意：不能拿 commit sha 当 base_tree）
const baseCommit = await api('GET', `/git/commits/${base}`);
const baseTree = baseCommit.tree.sha;

// 幂等：远端树已等于本地树 ⇒ 内容已同步
if (baseTree === rootTree && !FORCE_COMMIT) {
  console.log(`✅ 远端 ${base.slice(0, 8)} 的树已与本地一致（${rootTree}），内容已同步，无需推送`);
  process.exit(0);
}

// 一次性拉远端全部对象与树路径（唯一基准）
const remoteTreeResp = await api('GET', `/git/trees/${baseTree}?recursive=1`);
if (remoteTreeResp.truncated) console.warn('⚠️ 远端树 truncated=true，判断可能不准');
const remotePaths = new Map();  // path → tree sha（用于 base_tree）
const remoteObjs = new Set([baseTree]); // 远端已有对象 sha
for (const e of remoteTreeResp.tree) {
  remoteObjs.add(e.sha);
  if (e.type === 'tree') remotePaths.set(e.path, e.sha);
}
console.log(`远端对象 ${remoteObjs.size} 个 / 树路径 ${remotePaths.size} 个（基于 ${baseTree.slice(0, 8)}）`);

// 本地新树引用的全部对象（**只关心当前快照**，与远端快照同口径）
// ⚠️ 不要用 `git rev-list --objects <localSha>` —— 它包含**全部历史提交**的对象，
//    与远端「当前树快照」不是同一口径（实测 3527 vs 1335，差的全是历史旧版本 blob，
//    那些对象新树根本不引用，不需要上传）。
const LMAP = new Map();
const localTrees = [];
(function walkAll(treeSha, prefix) {
  for (const e of listTree(treeSha)) {
    const p = prefix ? `${prefix}/${e.name}` : e.name;
    LMAP.set(p, { path: p, mode: e.mode, type: e.type, sha: e.sha });
    if (e.type === 'tree') { localTrees.push({ sha: e.sha, path: p }); walkAll(e.sha, p); }
  }
})(rootTree, '');
const owned = [...new Set([...LMAP.values()].map((e) => e.sha))].filter((s) => !remoteObjs.has(s));
console.log(`本地快照条目 ${LMAP.size} 个 / 本地独有对象 ${owned.length} 个（远端快照 ${remoteObjs.size} 个对象）`);

if (DRY) {
  for (const sha of owned) console.log(`  ${git('cat-file', '-t', sha)} ${sha}`);
  console.log('（--dry-run 结束）');
  process.exit(0);
}

// 1) 上传 blob（幂等：先探存在性）
const uploadedBlob = new Map();
for (const sha of owned) {
  if (git('cat-file', '-t', sha) !== 'blob') continue;
  try { await api('GET', `/git/blobs/${sha}`); uploadedBlob.set(sha, sha); continue; } catch { /* 需上传 */ }
  const buf = gitBuf('cat-file', 'blob', sha);
  // [2026-09-23] 400 malformed 曾在这里发生且无上下文 → 失败时把「哪个对象、多大、开头字节」
  // 打出来，否则只能盲猜（此前误以为是 Content-Type 缺失，实测小 blob 不带也 201）。
  try {
    const r = await api('POST', '/git/blobs', { content: buf.toString('base64'), encoding: 'base64' });
    uploadedBlob.set(sha, r.sha);
  } catch (e) {
    throw new Error(
      `blob ${sha}（${buf.length}B，${git('cat-file', '-t', sha)}，head=${buf.subarray(0, 32).toString('hex')}）上传失败：${e.message}`
    );
  }
  console.log(`  blob ${sha.slice(0, 8)} ${buf.length}B`);
}

// 2) 自底向上重建 tree：只传变更条目 + base_tree（localTrees 已在上面收集）
localTrees.sort((a, b) => b.path.split('/').length - a.path.split('/').length);

const uploadedTree = new Map();

function changedEntries(entries) {
  const out = [];
  for (const e of entries) {
    let sha = e.sha;
    let isChanged = !remoteObjs.has(e.sha);
    if (e.type === 'blob' && uploadedBlob.has(e.sha)) { sha = uploadedBlob.get(e.sha); isChanged = true; }
    else if (e.type === 'tree' && uploadedTree.has(e.sha)) { sha = uploadedTree.get(e.sha); isChanged = true; }
    if (isChanged) out.push({ path: e.name, mode: e.mode, type: e.type, sha });
  }
  return out;
}

for (const t of localTrees) {
  const entries = changedEntries(listTree(t.sha));
  if (!entries.length) { uploadedTree.set(t.sha, t.sha); continue; }
  const body = { tree: entries };
  const bt = remotePaths.get(t.path);
  if (bt) body.base_tree = bt;
  const res = await api('POST', '/git/trees', body);
  uploadedTree.set(t.sha, res.sha);
  console.log(`  tree ${t.path} ${t.sha.slice(0, 8)} -> ${res.sha.slice(0, 8)}${res.sha === t.sha ? ' ✅' : ''}`);
}

// 根树
{
  const entries = changedEntries(listTree(rootTree));
  const res = await api('POST', '/git/trees', { tree: entries, base_tree: baseTree });
  uploadedTree.set(rootTree, res.sha);
}
const newRootTree = uploadedTree.get(rootTree);
console.log(`新根树 ${newRootTree}${newRootTree === rootTree ? '  ✅ 与本地一致' : '  ⚠️ 与本地不一致'}`);

// 3) 建提交
const rawCommit = gitBuf('cat-file', 'commit', localSha).toString('utf8');
const idx = rawCommit.indexOf('\n\n');
const msg = rawCommit.slice(idx + 2).replace(/\n+$/, '');
const authorLine = rawCommit.split('\n').find((l) => l.startsWith('author '));
const am = authorLine.match(/^author (.+) <(.+)> (\d+) ([+-]\d{4})$/);
const iso = new Date(Number(am[3]) * 1000).toISOString();
const newCommit = await api('POST', '/git/commits', {
  message: msg, tree: newRootTree, parents: [base],
  author: { name: am[1], email: am[2], date: iso },
  committer: { name: am[1], email: am[2], date: iso },
});
console.log(`新提交 ${newCommit.sha}${newCommit.sha === localSha ? '  ✅ 与本地 sha 相同' : '  （sha 不同，以树校验为准）'}`);

// 4) 校验（先校验，再动 ref —— 避免把坏结果推上去）
console.log('\n--- 校验远端树 vs 本地树 ---');
const LM = LMAP;
const RM = new Map(remoteTreeResp.tree.map((e) => [e.path, e]));

// 用"新根树"递归拉一次做真正校验（remoteTreeResp 是旧 base 的）
const verifyResp = await api('GET', `/git/trees/${newRootTree}?recursive=1`);
const VM = new Map(verifyResp.tree.map((e) => [e.path, e]));

let diff = 0;
for (const [p, le] of LM) {
  const ve = VM.get(p);
  if (!ve || ve.sha !== le.sha || ve.mode !== le.mode || ve.type !== le.type) {
    if (diff < 20) console.log(`  ❌ ${p}  本地 ${le.sha.slice(0, 8)}/${le.mode}  远端 ${ve ? ve.sha.slice(0, 8) + '/' + ve.mode : '<缺失>'}`);
    diff++;
  }
}
for (const [p] of VM) if (!LM.has(p)) { if (diff < 20) console.log(`  ⚠️ 远端多出 ${p}`); diff++; }
console.log(`本地 ${LM.size} / 远端 ${VM.size} 条目，差异 ${diff}`);
void RM;

if (diff !== 0 || newRootTree !== rootTree) {
  console.error('\n❌ 校验未通过，**不更新 ref**（远端保持原状）。请复查后重试。');
  writeFileSync('.push-via-api-result.json', JSON.stringify({ ok: false, localSha, base, diff, localTree: rootTree, newRootTree }, null, 2));
  process.exit(1);
}

// 5) 更新 ref
await api('PATCH', `/git/refs/heads/${BRANCH}`, { sha: newCommit.sha, force: true });
console.log(`ref ${BRANCH} -> ${newCommit.sha}`);

writeFileSync('.push-via-api-result.json', JSON.stringify({
  ok: true, owner: OWNER, repo: REPO, branch: BRANCH, localSha, base, newCommit: newCommit.sha,
  localTree: rootTree, newRootTree, diff, entries: { local: LM.size, remote: VM.size },
}, null, 2));
console.log('\n✅ 推送完成且内容零失真');
