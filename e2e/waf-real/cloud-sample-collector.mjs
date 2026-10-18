// ============================================================================
// cloud-sample-collector.mjs —— 商业云 WAF 真机样本采集器（P0-1）
//
// 为什么存在：台账 `waf-fingerprint-coverage` 的剩余缺口是「商业云 WAF 真机样本」
// （62 家指纹 61 家无真机证据；D89 的外部对拍是 wafw00f 规则**构造样本**，不是抓包实录）。
// 本脚本把「真机样本」从手抄变成可复现流程：
//   ① 对**授权目标**发一次良性 GET（与指纹阶段同行为，零攻击载荷、不发任何注入 payload）；
//   ② 取响应 status/headers/body，喂本仓 WafIdentifier 识别；
//   ③ 命中的厂商 + 其命中的响应特征 → 写入 `server/tests/fixtures/waf-real-samples.json`；
//   ④ 守卫 `server/tests/wafRealSamples.guard.test.js` 在样本非空后逐条断言可识别 + 零误报。
//
// ⚠️ 红线（与 AGENTS.md §0 一致）：
//   · 只能对**你有权测试**的目标跑；目标域名为你所有或已获书面授权。
//   · 本脚本默认**不发送任何攻击载荷**。若要取「拦截页」形态的样本：
//     在授权目标上自行触发一次拦截（curl 带一条 SQLi 特征），把响应经
//     `--from-json` 导入 —— 不要把攻击请求交给本脚本自动打。
//
// 用法：
//   node e2e/waf-real/cloud-sample-collector.mjs --url https://example.com
//   node e2e/waf-real/cloud-sample-collector.mjs --url https://example.com --vendor Cloudflare
//   node e2e/waf-real/cloud-sample-collector.mjs --from-json ./capture.json
//      （capture.json: {"status":403, "headers":{"cf-ray":"x","server":"cloudflare"},
//                       "body":"...", "note":"自已在授权目标上触发的拦截页"}）
//   --dry-run        只打印会写什么，不落盘
//   --expect <vendor> 识别结果必须含该厂商，否则 exit 2（防把误识别的响应当样本）
// ============================================================================
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const SNAPSHOT = resolve(here, '../../server/tests/fixtures/waf-real-samples.json');

const { WafIdentifier } = await import(pathToFileURL(resolve(here, '../../server/src/core/waf/WafIdentifier.js')));

function parseArgs() {
  const argv = process.argv.slice(2);
  const get = (k) => {
    const i = argv.indexOf(k);
    return i >= 0 && argv[i + 1] ? argv[i + 1] : undefined;
  };
  const has = (k) => argv.includes(k);
  return {
    url: get('--url'),
    vendor: get('--vendor'),
    fromJson: get('--from-json'),
    expect: get('--expect'),
    dryRun: has('--dry-run'),
  };
}

async function benignFetch(url) {
  // 带常见浏览器 UA；跟随重定向；超时 15s。仅 GET，不带任何 SQL 特征。
  const res = await fetch(url, {
    headers: { 'user-agent': 'Mozilla/5.0 (compatible; sqli-scanner/1.0; fingerprint-collector)' },
    redirect: 'follow',
    signal: AbortSignal.timeout(15000),
  });
  const body = (await res.text()).slice(0, 4096);
  // fetch 的 headers 是 Headers 对象 → 转普通对象（数组值逗号拼接，与 getHeader 口径一致）
  const headers = {};
  res.headers.forEach((v, k) => { headers[k] = v; });
  return { status: res.status, headers, body };
}

/** 把一条真机响应转成与 wafw00f 快照对齐的样本条目（仅存命中该厂商的特征） */
function toSampleEntry(ours, resp, extra) {
  const id = new WafIdentifier();
  const cand = (id.identify(resp, {}) || []).find((c) => c.vendor === ours);
  if (!cand) return null;
  // evidence 形如 "header: cf-ray; header: server~/cloudflare/i" → 逐条拆成可复核的 (key, value)
  const matches = [];
  for (const e of cand.evidence.split('; ')) {
    const m = e.match(/^header:\s*(\S+)(?:~([\s\S]+))?$/);
    if (m) {
      const key = m[1].toLowerCase();
      const val = resp.headers?.[key] ?? '';
      matches.push({ key, value: String(val).slice(0, 120) });
    }
  }
  if (matches.length === 0) return null;
  return {
    ours,
    kind: 'header',
    key: matches[0].key,
    value: matches[0].value,
    sourceRule: 'real-capture',
    capturedAt: new Date().toISOString(),
    ...(extra.target ? { target: extra.target } : {}),
    ...(resp.status ? { status: resp.status } : {}),
    evidence: cand.evidence,
  };
}

function loadSnapshot() {
  if (!existsSync(SNAPSHOT)) return { samples: [] };
  return JSON.parse(readFileSync(SNAPSHOT, 'utf8'));
}

function saveSnapshot(snap) {
  mkdirSync(dirname(SNAPSHOT), { recursive: true });
  const out = {
    _comment: '商业云 WAF 真机样本快照（real capture，非构造）。由 e2e/waf-real/cloud-sample-collector.mjs 写入；守卫 server/tests/wafRealSamples.guard.test.js 消费。',
    _source: '对授权目标的真实响应抓包实录',
    samples: snap.samples,
  };
  writeFileSync(SNAPSHOT, JSON.stringify(out, null, 2) + '\n', 'utf8');
}

async function main() {
  const args = parseArgs();
  if (!args.url && !args.fromJson) {
    console.error('用法：--url <授权目标> 或 --from-json <抓包文件>；--dry-run 预览；--expect <vendor> 强制校验');
    process.exit(2);
  }

  const snap = loadSnapshot();
  const seen = new Set(snap.samples.map((s) => `${s.ours}:${s.key}:${s.value}`));
  const results = [];
  const fail = [];

  const record = (resp, target, note) => {
    const id = new WafIdentifier();
    const cands = id.identify(resp, {}) || [];
    const ours = args.expect
      ? args.expect
      : (cands.find((c) => c.vendor !== 'generic_block') || {}).vendor;
    if (!ours) {
      const msg = `[${target}] 未识别出厂商候选：${cands.length ? cands.map((c) => c.vendor).join(',') : '无'}`;
      console.warn(`  ⚠️ ${msg}`);
      fail.push(msg);
      return;
    }
    if (args.expect && !cands.some((c) => c.vendor === args.expect)) {
      const msg = `[${target}] --expect ${args.expect} 但识别结果仅 ${cands.map((c) => c.vendor).join(',') || '无'}`;
      console.warn(`  ⚠️ ${msg}`);
      fail.push(msg);
      return;
    }
    const entry = toSampleEntry(ours, resp, { target });
    if (!entry) {
      const msg = `[${target}] 命中 ${ours} 但 evidence 无法解析为 header 特征（当前框架只收 header 形态）`;
      console.warn(`  ⚠️ ${msg}`);
      fail.push(msg);
      return;
    }
    const dedupKey = `${entry.ours}:${entry.key}:${entry.value}`;
    if (seen.has(dedupKey)) {
      console.log(`  · ${ours}（${entry.evidence}）：已存在，跳过`);
      return;
    }
    seen.add(dedupKey);
    results.push(entry);
    console.log(`  ✓ ${ours}（${entry.evidence}）${note ? '—— ' + note : ''}`);
  };

  if (args.fromJson) {
    const cap = JSON.parse(readFileSync(args.fromJson, 'utf8'));
    record({ status: cap.status ?? 0, headers: cap.headers ?? {}, body: cap.body ?? '' }, args.fromJson, cap.note || '抓包导入');
  } else if (args.url) {
    const u = args.url.replace(/\/$/, '');
    console.log(`[采集] ${u}（良性 GET，零攻击载荷）`);
    const resp = await benignFetch(u);
    console.log(`  HTTP ${resp.status} · headers=${Object.keys(resp.headers).length} · body=${resp.body.length}B`);
    record(resp, u, '良性 GET');
  }

  if (fail.length) {
    console.error(`\n[未写入] ${fail.length} 条失败 —— 不落盘脏样本：\n  - ${fail.join('\n  - ')}`);
    if (results.length) console.warn(`另有 ${results.length} 条可用样本被跳过（因为本次有失败），用 --expect 只采集已知厂商或 --dry-run 校验`);
    process.exit(2);
  }

  if (results.length === 0) {
    console.log('\n无新样本（目标响应未被识别为任何 WAF，或全部已存在）—— 符合预期时不是失败；');
    console.log('如需「拦截页」形态样本：在授权目标上自行触发一次拦截，--from-json 导入抓包。');
    return;
  }

  console.log(`\n新样本 ${results.length} 条：` + results.map((r) => `${r.ours}(${r.key})`).join(', '));
  if (args.dryRun) {
    console.log('[dry-run] 未落盘。以下为将写入的条目：');
    console.log(JSON.stringify(results, null, 2));
    return;
  }
  snap.samples.push(...results);
  saveSnapshot(snap);
  console.log(`[已写入] ${SNAPSHOT}（累计 ${snap.samples.length} 条）`);
  console.log('下一步：node --test server/tests/wafRealSamples.guard.test.js 验证守卫，再在台账确认转 verified 的判据。');
}

try {
  await main();
} catch (e) {
  console.error(`[收集器未预期异常] ${e && e.stack ? e.stack : e}`);
  process.exit(1);
}