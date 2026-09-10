// 编码态探针：union 门控探针在「真实 HTTP（URL 编码）」下到底命中哪条 CRS 规则
// 背景：diag-blocked.mjs 用解码态静态评估判「通过」，但真实重跑时真/假探针响应同长（138B）→ 疑被拦。
// 本脚本同时给出三种视角，定位差异：
//   ① 解码态静态评估（args = 解码值）
//   ② 编码态静态评估（queryString/uri = 原始编码串）
//   ③ 真实 HTTP 请求（Express + CRS 中间件，返回 403 页面里的 ruleId）
import { pathToFileURL } from 'node:url';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import { evaluate } from './crs-engine.js';

const require = createRequire(new URL('../../server/package.json', import.meta.url));
const express = require('express');
const HERE = dirname(fileURLToPath(import.meta.url));
const { fromExpress } = await import(pathToFileURL(resolve(HERE, './crs-engine.js')).href);

const CASES = [
  ['str 真探针', 'name', "alice' AND 1=1#"],
  ['str 假探针', 'name', "alice' AND 1=2#"],
  ['str 裸（未套 tamper）', 'name', "alice' AND 1=1-- -"],
  ['num 真探针', 'id', '1 AND 1=1#'],
  ['union 标记探测', 'id', "1 UNION SELECT 'SQLISCANNER0'#"],
  ['union ORDER BY', 'id', '1 ORDER BY 3#'],
];

console.log('=== ① 解码态静态评估（args 为解码值）===');
for (const [label, param, v] of CASES) {
  const r = evaluate({ uri: `/${param}?${param}=1`, queryString: `${param}=1`, args: { [param]: v }, cookies: {}, headers: {} });
  console.log(`  ${label.padEnd(22)} ${r.blocked ? '拦 ' + r.ruleId : '过'}`);
}

console.log('\n=== ② 编码态静态评估（queryString/uri 为原始编码串）===');
for (const [label, param, v] of CASES) {
  const enc = `${param}=${encodeURIComponent(v)}`;
  const r = evaluate({
    uri: `/${param}?${enc}`,
    queryString: enc,
    args: { [param]: v },
    cookies: {},
    headers: {},
  });
  console.log(`  ${label.padEnd(22)} ${r.blocked ? '拦 ' + r.ruleId : '过'}`);
}

console.log('\n=== ③ 真实 HTTP 请求（Express + CRS 中间件）===');
const app = express();
app.use((req, res, next) => {
  const v = evaluate(fromExpress(req));
  if (v.blocked) return res.status(403).send(`BLOCKED rule=${v.ruleId}`);
  next();
});
app.get('/str', (req, res) => res.send(`OK name=${req.query.name}`));
const server = app.listen(0);
await new Promise((r) => server.once('listening', r));
const port = server.address().port;
for (const [label, param, v] of CASES) {
  const url = `http://127.0.0.1:${port}/str?${param}=${encodeURIComponent(v)}`;
  const res = await fetch(url);
  const body = await res.text();
  console.log(`  ${label.padEnd(22)} status=${res.status} ${body.slice(0, 60)}`);
}
server.close();
process.exit(0);
