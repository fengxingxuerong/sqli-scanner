// e2e/recall-lab/safe-lab-server.js
// ============================================================================
// 无漏洞靶场（false-positive lab）：所有输入均经安全处理（参数化/白名单/过滤），
// 用于验证引擎对「安全目标」不误报。与 recall-lab（受感染靶场）互补。
//
// 端点设计（每个都模拟真实安全编码）：
//   GET /strict?id=1     数字白名单（/^\d+$/ 校验，非法即 400）
//   GET /param?q=x       参数化查询语义（输入原样回显于安全上下文，无注入面）
//   GET /escape?name=x   转义型（单引号转义，无法闭合）
//   GET /noecho?id=1     无回显（输入不反映在响应里）
//   GET /json?key=x      JSON 数值型回显（Content-Type: application/json）
//   POST /login?u=&p=   登录式（输入进不可见存储，无任何 SQL 语义）
// ============================================================================

import http from 'node:http';

function html(body, title = 'Safe App') {
  return `<!DOCTYPE html><html><head><title>${title}</title></head><body>
${body}</body></html>`;
}

export function createSafeLab() {
  const stats = { total: 0, byPath: {} };
  const resetStats = () => { stats.total = 0; stats.byPath = {}; };

  const server = http.createServer((req, res) => {
    stats.total++;
    let url;
    try {
      url = new URL(req.url, 'http://safe-lab.local');
    } catch {
      res.writeHead(400, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end(html('<h1>400 Bad Request</h1>'));
    }
    const path = url.pathname;
    stats.byPath[path] = (stats.byPath[path] || 0) + 1;

    if (req.method === 'GET' && path === '/strict') {
      const id = url.searchParams.get('id') || '';
      if (!/^\d+$/.test(id)) {
        res.writeHead(400, { 'Content-Type': 'text/html; charset=utf-8' });
        return res.end(html('<h1>400 Bad Request</h1><p>id 必须为数字</p>'));
      }
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end(html(`<h1>Item #${id}</h1><p>stored item detail</p>`));
    }

    if (req.method === 'GET' && path === '/param') {
      const q = url.searchParams.get('q') || '';
      // 参数化查询语义：输入仅作为「显示的文本」存在，任何 SQL 关键字均无效果
      const safe = q.replace(/</g, '&lt;');
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end(html(`<h1>Search</h1><p>Results for: ${safe}</p><p>No results found.</p>`));
    }

    if (req.method === 'GET' && path === '/escape') {
      let name = url.searchParams.get('name') || '';
      // 转义型防护：单引号替换为 ''（SQL 转义语义），无法闭合
      name = name.replace(/'/g, "''");
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end(html(`<h1>Profile: ${name}</h1><p>escaped output</p>`));
    }

    if (req.method === 'GET' && path === '/noecho') {
      const id = url.searchParams.get('id') || '1';
      // 无回显：输入不进入任何响应（扫描器无从比较真假差异）
      void id;
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end(html('<h1>Dashboard</h1><p>You are logged in.</p>'));
    }

    if (req.method === 'GET' && path === '/json') {
      const key = url.searchParams.get('key') || '';
      // JSON API：数值型回显，输入永远进字符串值，无法改变结构
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ key, value: 0, ok: true }));
    }

    if (req.method === 'POST' && path === '/login') {
      const u = url.searchParams.get('u') || '';
      // 登录式：输入进不可见会话（无 SQL 语义暴露）
      void u;
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end(html('<h1>Welcome!</h1><p>Login successful.</p>'));
    }

    res.writeHead(404, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(html('<h1>404</h1>'));
  });

  return { server, stats, resetStats };
}

// 仅在直接执行时监听（被 import 时不自动启动）
if (process.argv[1] && import.meta.url === `file://${process.argv[1].replace(/\\/g, '/')}`) {
  const { server } = createSafeLab();
  const PORT = Number(process.env.SAFE_LAB_PORT) || 8124;
  server.listen(PORT, '127.0.0.1', () => {
    console.log(`[safe-lab] 无漏洞靶场 http://127.0.0.1:${PORT}`);
    console.log('[safe-lab] endpoints: /strict /param /escape /noecho /json (GET), /login (POST)');
  });
}

export default createSafeLab;