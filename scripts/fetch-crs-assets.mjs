// ============================================================================
// scripts/fetch-crs-assets.mjs —— 拉取 OWASP CRS 官方资产并落盘（可离线复用）
//
// 为什么需要它：仓库里的 WAF 数字全部出自**自实现的 SecRule 执行器**，而本机没有 Docker / Go，
// 跑不了真 ModSecurity/Coraza。退而求其次的正确做法不是"再测一遍自己的靶场"，而是
// **拿 CRS 项目自己维护的回归用例**（每条都带"该拦 / 不该拦"的期望）来验收我们的执行器 ——
// 那是规则作者写的断言，不是我们自证的循环。
//
// 用法：
//   node scripts/fetch-crs-assets.mjs              # 下载（已存在且哈希一致则跳过）
//   node scripts/fetch-crs-assets.mjs --force      # 强制重下
//   node scripts/fetch-crs-assets.mjs --verify-rules  # 只校验入库规则文件是否与上游逐字节一致
//
// 落盘：
//   e2e/waf-real/crs/tests/<族>/<ruleId>.yaml   官方回归用例
//   e2e/waf-real/crs/tests/manifest.json        来源 tag + 每个文件的 sha256（可复核、可离线）
//
// ⚠️ 只下载我们**真正加载的规则族**（942 SQLi）。把别的族也拉进来只会稀释一致率却测不到东西：
//    执行器一次只吃一个 conf（见 crs-engine.js evaluate 的 confPath 默认值）。
// ============================================================================
import { mkdirSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '..');
const CRS_TAG = 'v4.1.0'; // 与入库规则文件头注释（"OWASP CRS ver.4.1.0"）对齐；升级时两处一起改
const API = 'https://api.github.com/repos/coreruleset/coreruleset/contents';
const RAW = 'https://raw.githubusercontent.com/coreruleset/coreruleset';

// 族 → { dir: 上游回归目录, conf: 入库规则文件 }
const FAMILIES = [
  { key: '942', dir: 'REQUEST-942-APPLICATION-ATTACK-SQLI', conf: 'crs/REQUEST-942-SQLI.conf', upstreamConf: 'rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf' },
  // 930（LFI）规则原文已入库但执行器默认不加载，先只校验规则文件本身、不下用例
  { key: '930', dir: 'REQUEST-930-APPLICATION-ATTACK-LFI', conf: 'crs/REQUEST-930.conf', upstreamConf: 'rules/REQUEST-930-APPLICATION-ATTACK-LFI.conf', tests: false },
];

const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');

async function get(url, asText = true) {
  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      const res = await fetch(url, {
        headers: { 'User-Agent': 'sqli-scanner-crs-fetcher', Accept: asText ? 'text/plain' : 'application/octet-stream' },
        signal: AbortSignal.timeout(45000),
      });
      if (res.status === 404) return { notFound: true };
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return { body: asText ? await res.text() : Buffer.from(await res.arrayBuffer()) };
    } catch (e) {
      if (attempt === 3) throw new Error(`取不到 ${url}（3 次重试）：${e.message}`);
      await new Promise((r) => setTimeout(r, 800 * attempt));
    }
  }
  return { notFound: true };
}

const listYamls = async (dir) => {
  const url = `${API}/${dir}?ref=${CRS_TAG}`;
  const res = await fetch(url, { headers: { 'User-Agent': 'sqli-scanner-crs-fetcher', Accept: 'application/vnd.github+json' }, signal: AbortSignal.timeout(45000) });
  if (!res.ok) throw new Error(`列目录失败 ${dir}: HTTP ${res.status}`);
  const json = await res.json();
  return json.filter((f) => f.type === 'file' && f.name.endsWith('.yaml')).map((f) => f.name);
};

const manifestPath = resolve(ROOT, 'e2e/waf-real/crs/tests/manifest.json');
const readManifest = () => (existsSync(manifestPath) ? JSON.parse(readFileSync(manifestPath, 'utf8')) : { tag: CRS_TAG, files: {} });

async function fetchTests(force) {
  const manifest = readManifest();
  if (manifest.tag !== CRS_TAG) { manifest.tag = CRS_TAG; }
  let added = 0;
  let skipped = 0;
  let changed = 0;
  for (const fam of FAMILIES.filter((f) => f.tests !== false)) {
    const names = await listYamls(`tests/regression/tests/${fam.dir}`);
    for (const name of names) {
      const rel = `crs/tests/${fam.key}/${name}`;
      const abs = resolve(ROOT, 'e2e/waf-real', rel);
      const url = `${RAW}/${CRS_TAG}/tests/regression/tests/${fam.dir}/${name}`;
      const { body } = await get(url);
      const hash = sha256(body);
      const prev = manifest.files[rel]?.sha256;
      if (!force && existsSync(abs) && prev === hash) { skipped++; manifest.files[rel] = { sha256: hash, bytes: body.length, upstream: url }; continue; }
      if (existsSync(abs) && prev && prev !== hash) changed++;
      mkdirSync(dirname(abs), { recursive: true });
      writeFileSync(abs, body);
      manifest.files[rel] = { sha256: hash, bytes: body.length, upstream: url };
      added++;
    }
  }
  manifest.fetchedAt = new Date().toISOString();
  manifest.tag = CRS_TAG;
  writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));
  console.log(`[crs] 用例落盘：新增/更新 ${added}、哈希一致跳过 ${skipped}、内容变更 ${changed}；共 ${Object.keys(manifest.files).length} 个文件（tag ${CRS_TAG}）`);
}

/**
 * 校验入库规则文件是否与上游一致。
 *
 * [GATE-FIX 2026-09-20] 默认走**离线核对**：磁盘字节 vs manifest 里记录的上游 sha256。
 * 原实现每次都要现拉 raw.githubusercontent.com 比哈希 —— 门禁因此继承了一个外部服务的可用性，
 * 本机 ci:local 一轮就被网络抖动刷成一次假红（代码一字未改）。而"入库文件没被人改过"这个
 * 不变量本来就不需要联网：抓取那一刻记录的上游哈希就是证据。
 * 要连上游现拉是**升级规则版本时**的动作，显式加 --online。
 */
async function verifyRules(online) {
  const manifest = readManifest();
  manifest.rules ||= {};
  let bad = 0;
  let bootstrapped = 0;
  for (const fam of FAMILIES) {
    const abs = resolve(ROOT, 'e2e/waf-real', fam.conf);
    if (!existsSync(abs)) { console.log(`  ❌ ${fam.conf} 不存在`); bad++; continue; }
    const local = sha256(readFileSync(abs));
    const rec = manifest.rules[fam.conf];
    if (!rec) {
      if (!online) {
        // 首次：离线没有可比基线，必须联网抓一次并记账（否则这一条就永远是"看起来通过"）
        console.log(`  …  ${fam.conf} 无入库快照，联网抓一次建立基线（此后离线可判）`);
      }
      const { body, notFound } = await get(`${RAW}/${CRS_TAG}/${fam.upstreamConf}`);
      if (notFound) { console.log(`  ?  ${fam.conf} → 上游没有 ${fam.upstreamConf}（文件名与上游不同，需人工核对来源）`); continue; }
      manifest.rules[fam.conf] = { sha256: sha256(body), bytes: body.length, upstream: `${RAW}/${CRS_TAG}/${fam.upstreamConf}`, tag: CRS_TAG };
      bootstrapped++;
      const same = local === manifest.rules[fam.conf].sha256;
      if (!same) bad++;
      console.log(`  ${same ? '✅' : '❌'} ${fam.conf}  ${local.slice(0, 12)}… ${same ? '== 上游（已记账）' : '!= 上游'}`);
      continue;
    }
    const same = local === rec.sha256;
    if (!same) bad++;
    console.log(
      `  ${same ? '✅' : '❌'} ${fam.conf}  ${local.slice(0, 12)}… ${same ? `== 入库快照（tag ${rec.tag}，离线核对）` : `!= 入库快照 ${rec.sha256.slice(0, 12)}…（文件被改过？tag ${rec.tag}）`}`
    );
    if (online) {
      const { body, notFound } = await get(rec.upstream);
      if (notFound) console.log(`     ? 在线核对跳过：上游取不到 ${rec.upstream}`);
      else {
        const remote = sha256(body);
        console.log(`     在线核对：${remote === rec.sha256 ? '入库快照与上游一致' : `上游已变 ${remote.slice(0, 12)}…（快照过期，需 --force 重抓）`}`);
        if (remote !== rec.sha256) bad++;
      }
    }
  }
  if (bootstrapped) writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));
  console.log(
    bad
      ? `\n[crs] 规则原文一致性：${bad} 处不符 —— README「官方规则原文」的说法需要修正`
      : `\n[crs] 规则原文一致性：全部一致（离线核对入库快照${online ? ' + 上游在线核对' : ''}；升级规则后跑 --verify-rules=online 复验）`
  );
  process.exitCode = bad ? 1 : 0;
}

const arg = process.argv.find((a) => a.startsWith('--verify-rules')) ? '--verify-rules' : process.argv.find((a) => a.startsWith('--'));
if (arg === '--verify-rules') await verifyRules(process.argv.includes('--verify-rules=online') || process.argv.includes('--online'));
else await fetchTests(process.argv.includes('--force'));
