// 诊断探针：判断 `POST /git/blobs -> 400 malformed request` 是「内容问题」还是「传输偶发」。
// 做法：把目标 blob 按 全量 / 98k / 95k / 90k / 60k / 30k + 尾部 30k 逐段上传，看状态码分布。
//   全段都 400 → 内容问题；只有某次 400 且重发 201 → 传输偶发（本机代理链路，2026-09-23 实测）。
// 跑法：GH_TOKEN=xxx node scripts/probe-blob-400.mjs [<blob-sha>]
// ⚠️ 必须走 env 的 https_proxy（node fetch 不读 env 代理，直连 api.github.com 会 UND_ERR_CONNECT_TIMEOUT）。
import { execFileSync } from 'node:child_process';

const TOKEN = process.env.GH_TOKEN;
const SHA = process.argv[2] || '278844a3131faa8af54786646374ae9849863492';
const REPO = 'fengxingxuerong/sqli-scanner';

// 本机 api.github.com 直连超时，必须走 env 里的本地代理（node fetch 不读 env 代理）
const PROXY = process.env.https_proxy || process.env.HTTPS_PROXY;
let dispatcher;
try {
  const { ProxyAgent } = await import('undici');
  if (PROXY) dispatcher = new ProxyAgent({ uri: PROXY });
} catch { /* 无 undici 则直连 */ }
console.log('proxy =', PROXY || '(直连)');

const buf = execFileSync('git', ['cat-file', 'blob', SHA], { maxBuffer: 1 << 28 });
console.log('blob', SHA.slice(0, 8), buf.length, 'B');

async function post(b, label) {
  const res = await fetch('https://api.github.com/repos/' + REPO + '/git/blobs', {
    method: 'POST',
    headers: {
      Authorization: 'Bearer ' + TOKEN,
      Accept: 'application/vnd.github+json',
      'User-Agent': 'probe-blob-400',
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ content: b.toString('base64'), encoding: 'base64' }),
    dispatcher,
  });
  const t = await res.text();
  console.log(String(res.status).padEnd(4), label.padEnd(14), t.slice(0, 110).replace(/\n/g, ' '));
  return res.ok;
}

const cuts = [buf.length, 98000, 95000, 90000, 60000, 30000];
for (const n of cuts) {
  if (n > buf.length) continue;
  await post(buf.subarray(0, n), 'head ' + n);
}
// 尾部 30000（排除「只有前 N 字节」没覆盖到的后段内容）
await post(buf.subarray(buf.length - 30000), 'tail 30000');
