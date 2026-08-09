// 临时靶机：简单布尔注入（GET ?id=1），TRUE→正常页（==基线），FALSE→DENIED（divergent）。
// 用于 --no-keep-alive 与默认 keepAlive 的 CLI e2e 验证。
import http from 'node:http';

const NORMAL = 'Welcome normal page id=1';
const DENIED = 'ACCESS DENIED';

const server = http.createServer((req, res) => {
  const u = new URL(req.url, 'http://x');
  const id = u.searchParams.get('id') || '';
  // TRUE 条件：'1'='1  → 正常页；否则 DENIED
  const isTrue = id.includes("'1'='1") || id === '1';
  // 基线请求 id=1 → 正常页（与 TRUE 一致）
  res.setHeader('Content-Type', 'text/plain; charset=utf-8');
  res.end(isTrue ? NORMAL : DENIED);
});

server.listen(4569, '127.0.0.1', () => {
  console.log('target-up port=4569');
});
