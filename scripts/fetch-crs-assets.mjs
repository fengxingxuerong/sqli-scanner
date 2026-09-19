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

/** 校验入库规则文件与上游同 tag 是否逐字节一致（README 的"官方规则原文"要靠它，而不是靠注释）。 */
async function verifyRules() {
  let bad = 0;
  for (const fam of FAMILIES) {
    const abs = resolve(ROOT, 'e2e/waf-real', fam.conf);
    if (!existsSync(abs)) { console.log(`  ❌ ${fam.conf} 不存在`); bad++; continue; }
    const local = sha256(readFileSync(abs));
    const { body, notFound } = await get(`${RAW}/${CRS_TAG}/${fam.upstreamConf}`);
    if (notFound) { console.log(`  ?  ${fam.conf} → 上游没有 ${fam.upstreamConf}（文件名与上游不同，需人工核对来源）`); continue; }
    const remote = sha256(body);
    const same = local === remote;
    if (!same) bad++;
    console.log(`  ${same ? '✅' : '❌'} ${fam.conf}  ${local.slice(0, 12)}… ${same ? '== 上游' : `!= 上游 ${remote.slice(0, 12)}…（${body.length}B vs ${readFileSync(abs).length}B）`}`);
  }
  console.log(bad ? `\n[crs] 规则原文一致性：${bad} 处不符 —— README「官方规则原文」的说法需要修正` : '\n[crs] 规则原文一致性：全部逐字节相同');
  process.exitCode = bad ? 1 : 0;
}

const arg = process.argv.find((a) => a.startsWith('--'));
if (arg === '--verify-rules') await verifyRules();
else await fetchTests(arg === '--force');
