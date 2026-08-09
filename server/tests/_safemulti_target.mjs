// 临时靶机：主目标布尔注入（GET ?id=1，TRUE→正常页，FALSE→DENIED）；
// 另提供两个安全 URL 路径：/safe1 与 /safe2 始终返回稳定内容（供多 safe-url 随机轮询 e2e）。
import http from 'node:http';

const NORMAL = 'Welcome normal page id=1';
const DENIED = 'ACCESS DENIED';
const SAFE1 = 'SAFE_PAGE_ONE_STABLE';
const SAFE2 = 'SAFE_PAGE_TWO_STABLE';

const server = http.createServer((req, res) => {
  const u = new URL(req.url, 'http://x');
  res.setHeader('Content-Type', 'text/plain; charset=utf-8');
  if (u.pathname === '/safe1') { res.end(SAFE1); return; }
  if (u.pathname === '/safe2') { res.end(SAFE2); return; }
  const id = u.searchParams.get('id') || '';
  const isTrue = id.includes("'1'='1") || id === '1';
  res.end(isTrue ? NORMAL : DENIED);
});

server.listen(4571, '127.0.0.1', () => console.log('target-up port=4571'));
