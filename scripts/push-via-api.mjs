#!/usr/bin/env node
/**
 * push-via-api.mjs —— 当 `git push` 被网络阻断时，改用 GitHub Git Data API 推送。
 *
 * 背景（2026-09-22 实测，本机网络）：
 *   - `api.github.com` 走代理 = 200（可用）
 *   - `codeload` / `objects.githubusercontent.com` = 301 / 404（可用）
 *   - `github.com` 走代理 = 000 / CONNECT tunnel failed 502
 *   - `github.com:443` 不走代理 = 000（21s 超时）
 *   → `github.com:443` 双向不通 ⇒ `git push` / `git ls-remote` 必失败，
 *     `env -u http_proxy ...`（旧招）本网络下无效。
 *
 * 原理：本仓库是私有库，git-over-HTTPS 走不通，但 REST API 通。
 *   因此用 API 手工搬运对象：
 *     git rev-list --objects  求本地独有对象
 *       → POST /git/blobs  上传 blob（base64）
 *       → POST /git/trees  自底向上重建 tree（复用远端已有子树）
 *       → POST /git/commits 建提交
 *       → PATCH /git/refs/heads/<branch>  更新引用
 *
 * 用法：
 *   export GH_TOKEN=$(printf 'protocol=https\nhost=github.com\n\n' \
 *     | "/c/Program Files/Git/mingw64/bin/git-credential-manager.exe" get \
 *     | sed -n 's/^password=//p')
 *   node scripts/push-via-api.mjs [--remote origin] [--branch master]
 *                                 [--local <sha>] [--base <sha>] [--dry-run]
 *
 * 设计要点：
 *   - **解析 tree 一律用 `-z`**：非 ASCII 路径在默认模式下会被 git 加引号 +
 *     八进制转义（实测 38 处），直接喂给 API 会产生**带字面引号的文件名**。
 *   - **message 尾部换行**：GitHub 建 commit 时会给 message 末尾补一个 `\n`，
 *     本地 commit 的 message 已自带 → 需先剥掉才能让字节与本地一致。
 *   - **重试**：代理下 socket 偶发 `UND_ERR_SOCKET` → 最多 6 次指数退避。
 *   - **幂等**：上传前先 `GET /git/blobs/<sha>` 探存在性 → 重跑秒过。
 *   - **校验**：推送后递归拉取远端树，与本地 `git ls-tree -r -t -z` 逐条比对
 *     path / mode / sha，报告差异数（比"commit sha 相等"更可靠）。
 *
 * 退出码：0 = 推送且校验通过；1 = 失败（含校验不通过）。
 */
import { execFileSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';

// ---------- 参数 ----------
const argv = process.argv.slice(2);
const opt = (name, def) => {
  const i = argv.indexOf(`--${name}`);
  return i >= 0 && argv[i + 1] ? argv[i + 1] : def;
};
const DRY = argv.includes('--dry-run');

const git = (...a) => execFileSync('git', a, { encoding: 'utf8', maxBuffer: 1 << 28 }).trim();
const gitBuf = (...a) => execFileSync('git', a, { maxBuffer: 1 << 28 });

const REMOTE = opt('remote', 'origin');
const BRANCH = opt('branch', 'master');
const LOCAL = opt('local', git('rev-parse', BRANCH));
const remoteUrl = git('remote', 'get-url', REMOTE);
const m = remoteUrl.match(/github\.com[:/]([^/]+)\/([^/.]+)(?:\.git)?$/);
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
  if (!res.ok) throw new Error(`${method} ${path} -> ${res.status}: ${text.slice(0, 400)}`);
  return text ? JSON.parse(text) : {};
}

async function api(method, path, body) {
  for (let i = 1; i <= 6; i++) {
    try {
      return await apiOnce(method, path, body);
    } catch (e) {
      const retriable = /fetch failed|UND_ERR_SOCKET|other side closed|ECONNRESET|502|timeout|EAI_AGAIN/i
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
const localSha = git('rev-parse', LOCAL);
const rootTree = git('rev-parse', `${LOCAL}^{tree}`);

// 远端当前 HEAD（base）
// 优先用本地已有的 remote-tracking / ls-remote（若可用）；否则退回 API。
let base = opt('base', '');
if (!base) {
  // 1) 本地已缓存的远端引用（fetch 可能不落 loose ref，故多试几个位置）
  try {
    base = git('rev-parse', `refs/remotes/${REMOTE}/${BRANCH}`);
  } catch { /* 继续 */ }
}
if (!base) {
  // 2) ls-remote（本网络下通常不通，但试一次成本很低）
  try {
    const out = git('ls-remote', REMOTE, `refs/heads/${BRANCH}`);
    base = (out.split(/\s+/)[0] || '').trim();
  } catch { /* 继续 */ }
}
if (!base) {
  // 3) API
  try {
    base = (await api('GET', `/git/refs/heads/${BRANCH}`)).object.sha;
  } catch (e) {
    console.error(`取远端 ${BRANCH} 失败（可能是空库）：${e.message}`);
    process.exit(1);
  }
}
if (!/^[0-9a-f]{40}$/.test(base)) { console.error(`base 非法：${base}`); process.exit(1); }
console.log(`本地 ${localSha}  tree ${rootTree}`);
console.log(`远端 ${base}`);

if (base === localSha) { console.log('✅ 已是最新，无需推送'); process.exit(0); }

// 幂等判定：远端 HEAD 的 tree 已等于本地 tree ⇒ 内容已同步（sha 不同可能只是 committer 字节差异）
try {
  const rc = await api('GET', `/git/commits/${base}`);
  if (rc.tree && rc.tree.sha === rootTree) {
    console.log(`✅ 远端 ${base.slice(0, 8)} 的树已与本地一致（${rootTree}），内容已同步，无需推送`);
    console.log('   （若需让 sha 也相同，可加 --force-commit 强制重建提交）');
    if (!argv.includes('--force-commit')) process.exit(0);
  }
} catch { /* 忽略，继续正常流程 */ }

// 收集本地对象；远端已有对象集优先用本地对象库判断（快）。
// 关键：base 本身可能**本地不存在**（例如 base 是上次 API 推送产生的提交）。
// 此时沿 base 的祖先链回退，取**第一个本地存在的提交**作为对象基准 —— 它包含的
// 对象集与 base 的差异只是那几次 API 推送新增的少量对象，成本可忽略。
const localObjs = new Set(git('rev-list', '--objects', localSha).split('\n').filter(Boolean).map((l) => l.split(' ')[0]));
let remoteObjs = null;
let baseForObjects = base;
try {
  remoteObjs = new Set(git('rev-list', '--objects', base).split('\n').filter(Boolean).map((l) => l.split(' ')[0]));
  console.log(`远端对象集（本地对象库，base=${base.slice(0, 8)}）${remoteObjs.size} 个`);
} catch {
  // base 本地不存在 → 通过 API 取它的 parent 链，找第一个本地有的
  console.log(`⚠️ 本地对象库不含 base=${base.slice(0, 8)} → 沿祖先链回退`);
  let cursor = base;
  const seen = [];
  for (let hop = 0; hop < 20; hop++) {
    let c;
    try { c = await api('GET', `/git/commits/${cursor}`); } catch { break; }
    const parents = (c.parents || []).map((p) => p.sha);
    if (!parents.length) break;
    const next = parents[0];
    let localHas = false;
    try { git('cat-file', '-t', next); localHas = true; } catch { localHas = false; }
    seen.push(`${cursor.slice(0, 8)}→${next.slice(0, 8)}${localHas ? ' ✅本地有' : ''}`);
    cursor = next;
    if (localHas) break;
  }
  console.log(`  祖先链: ${seen.join('  ')}`);
  try {
    remoteObjs = new Set(git('rev-list', '--objects', cursor).split('\n').filter(Boolean).map((l) => l.split(' ')[0]));
    baseForObjects = cursor;
    console.log(`  基准回退到 ${cursor.slice(0, 8)}（对象 ${remoteObjs.size} 个）`);
  } catch {
    console.log('  ⚠️ 祖先链上也没有本地对象 → 全量上传（首次推送场景）');
    remoteObjs = null;
  }
}

let owned;
if (remoteObjs) {
  owned = [...localObjs].filter((s) => !remoteObjs.has(s));
  console.log(`待处理本地独有对象 ${owned.length} 个（相对基准 ${baseForObjects.slice(0, 8)}）`);
} else {
  // 首次推送：全部对象都要上传，无需探测
  owned = [...localObjs];
  console.log(`待处理本地独有对象 ${owned.length} 个（无基准，全量）`);
}

if (DRY) {
  for (const sha of owned) console.log(`  ${git('cat-file', '-t', sha)} ${sha}`);
  console.log('（--dry-run 结束）');
  process.exit(0);
}

// 1) 上传 blob（幂等）
const uploadedBlob = new Map();
for (const sha of owned) {
  if (git('cat-file', '-t', sha) !== 'blob') continue;
  try { await api('GET', `/git/blobs/${sha}`); uploadedBlob.set(sha, sha); continue; } catch { /* 需上传 */ }
  const buf = gitBuf('cat-file', 'blob', sha);
  const r = await api('POST', '/git/blobs', { content: buf.toString('base64'), encoding: 'base64' });
  uploadedBlob.set(sha, r.sha);
  console.log(`  blob ${sha.slice(0, 8)} ${buf.length}B`);
}

// 2) 收集本地全部 tree（深度降序 → 自底向上）
const localTrees = [];
(function walk(treeSha, path) {
  for (const e of listTree(treeSha)) {
    if (e.type === 'tree') { localTrees.push({ sha: e.sha, path }); walk(e.sha, path ? `${path}/${e.name}` : e.name); }
  }
})(rootTree, '');
localTrees.sort((a, b) => b.path.split('/').length - a.path.split('/').length);

function remap(entries) {
  let changed = false;
  const out = entries.map((e) => {
    let sha = e.sha;
    if (e.type === 'blob' && uploadedBlob.has(e.sha)) { sha = uploadedBlob.get(e.sha); changed = true; }
    else if (e.type === 'tree' && uploadedTree.has(e.sha)) { sha = uploadedTree.get(e.sha); changed = true; }
    else if (remoteObjs && !remoteObjs.has(e.sha)) { changed = true; }
    else if (!remoteObjs) { changed = true; }
    return { path: e.name, mode: e.mode, type: e.type, sha };
  });
  return { out, changed };
}

const uploadedTree = new Map();
for (const t of localTrees) {
  let changed = !remoteObjs || !remoteObjs.has(t.sha);
  const r = remap(listTree(t.sha));
  changed = changed || r.changed;
  if (!changed) { uploadedTree.set(t.sha, t.sha); continue; }
  const res = await api('POST', '/git/trees',r.out);
  uploadedTree.set(t.sha, res.sha);
  if (res.sha !== t.sha) console.log(`  tree ${t.sha.slice(0, 8)} ${t.path} -> ${res.sha.slice(0, 8)}`);
}
let rootChanged = !remoteObjs || !remoteObjs.has(rootTree);
{
  const r = remap(listTree(rootTree));
  rootChanged = rootChanged || r.changed;
  if (rootChanged) {
    const res = await api('POST', '/git/trees',r.out);
    uploadedTree.set(rootTree, res.sha);
  } else uploadedTree.set(rootTree, rootTree);
}
const newRootTree = uploadedTree.get(rootTree);
console.log(`新根树 ${newRootTree}${newRootTree === rootTree ? '  ✅ 与本地一致' : '  ⚠️ 与本地不一致'}`);

// 3) 建提交（剥掉 message 尾部换行 —— GitHub 会补一个）
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
console.log(`新提交 ${newCommit.sha}${newCommit.sha === localSha ? '  ✅ 与本地 sha 相同' : '  （sha 与本地不同，内容以树校验为准）'}`);

// 4) 更新 ref
await api('PATCH', `/git/refs/heads/${BRANCH}`, { sha: newCommit.sha, force: true });
console.log(`ref ${BRANCH} -> ${newCommit.sha}`);

// 5) 校验：递归拉远端树，与本地逐条比对
console.log('\n--- 校验远端树 vs 本地树 ---');
const remoteTree = await api('GET', `/git/trees/${newRootTree}?recursive=1`);
if (remoteTree.truncated) console.warn('⚠️ 远端树返回 truncated=true，校验不完整');
const localRecurse = [];
(function walkAll(treeSha, prefix) {
  for (const e of listTree(treeSha)) {
    const p = prefix ? `${prefix}/${e.name}` : e.name;
    localRecurse.push({ path: p, mode: e.mode, type: e.type, sha: e.sha });
    if (e.type === 'tree') walkAll(e.sha, p);
  }
})(rootTree, '');
const LM = new Map(localRecurse.map((e) => [e.path, e]));
const RM = new Map(remoteTree.tree.map((e) => [e.path, e]));
let diff = 0;
for (const [p, le] of LM) {
  const re = RM.get(p);
  if (!re || re.sha !== le.sha || re.mode !== le.mode || re.type !== le.type) {
    console.log(`  ❌ ${p}  本地 ${le.sha.slice(0, 8)}/${le.mode}  远端 ${re ? re.sha.slice(0, 8) + '/' + re.mode : '<缺失>'}`);
    diff++;
  }
}
for (const [p] of RM) if (!LM.has(p)) { console.log(`  ⚠️ 远端多出 ${p}`); diff++; }
console.log(`本地 ${LM.size} / 远端 ${RM.size} 条目，差异 ${diff}`);
console.log(diff === 0 && newRootTree === rootTree ? '\n✅ 推送完成且内容零失真' : '\n⚠️ 校验未通过，请复查');

writeFileSync('.push-via-api-result.json', JSON.stringify({
  owner: OWNER, repo: REPO, branch: BRANCH, localSha, base, newCommit: newCommit.sha,
  localTree: rootTree, newRootTree, diff, entries: { local: LM.size, remote: RM.size },
}, null, 2));

process.exit(diff === 0 && newRootTree === rootTree ? 0 : 1);
