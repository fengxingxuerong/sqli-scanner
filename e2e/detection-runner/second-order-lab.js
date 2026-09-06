// e2e/detection-runner/second-order-lab.js
// ============================================================================
// 二阶注入靶场（Second-Order Injection Lab）
//
// 模拟二阶注入场景：用户输入先存储到数据库（第一次请求），再在另一个端点
// 被拼入 SQL 执行（第二次请求）。检测器需配置 secondUrl 来检测二阶注入。
//
// 端点：
//   POST /store?name=<input>     存储 name 到内存"数据库"
//   GET  /profile                 读取存储的 name，拼入 SQL 并"执行"
//                                布尔真假页：name 含 1=1 → 全表，name 含 1=2 → 空
//
// 场景：先 POST /store?name=1' AND '1'='1 -- - 存储恶意 payload，
//       再 GET /profile 检测真假差异（真=正常页，假=空页）。
// ============================================================================

import http from 'node:http';

export function createSecondOrderLab() {
  const stats = { total: 0, byPath: {} };
  const resetStats = () => { stats.total = 0; stats.byPath = {}; };

  // 内存"数据库"：存储最近一次 POST 的 name 值
  let storedName = 'alice';

  const server = http.createServer(async (req, res) => {
    stats.total++;
    let url;
    try {
      url = new URL(req.url, 'http://second-order-lab.local');
    } catch {
      res.writeHead(400, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end('<h1>400 Bad Request</h1>');
    }
    const path = url.pathname;
    stats.byPath[path] = (stats.byPath[path] || 0) + 1;

    // GET /store — 返回含 POST 表单的 HTML 页（供 TargetParser 发现存储点）
    if (req.method === 'GET' && path === '/store') {
      const html = `<html><body><h1>Update Profile</h1><form method="POST" action="/store"><input name="name" value="${storedName.replace(/</g, '&lt;')}"><button type="submit">Save</button></form><!-- ts=${Date.now()} --></body></html>`;
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end(html);
    }

    // POST /store?name=<input> — 存储 name 值（模拟写入数据库）
    if (req.method === 'POST' && path === '/store') {
      let body = '';
      for await (const chunk of req) body += chunk;
      // 兼容 JSON 和 URL-encoded 两种请求体格式
      let name = url.searchParams.get('name') || 'default';
      const ct = (req.headers['content-type'] || '').toLowerCase();
      if (ct.includes('application/json')) {
        try { name = JSON.parse(body).name || name; } catch { /* ignore */ }
      } else if (body) {
        try {
          const params = new URLSearchParams(body);
          name = params.get('name') || name;
        } catch { /* ignore */ }
      }
      storedName = name;
      if (process.env.DEBUG_SO_LAB) console.error(`[so-lab] POST /store body="${body.substring(0, 100)}" ct="${ct}" name="${name}"`);
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end(`<html><body><h1>Profile updated</h1><p>Name stored: ${name.replace(/</g, '&lt;')}</p><!-- ts=${Date.now()} --></body></html>`);
    }

    // GET /profile — 读取存储的 name，拼入 SQL "执行"
    // 模拟: SELECT * FROM users WHERE name='<storedName>'
    // 当 storedName 含 SQL 注入探针（如 ' 或 1'）时，模拟 SQL 报错（匹配 ERROR_SIG）
    // 当 storedName 为正常值时，返回正常页面（无报错特征）
    if (req.method === 'GET' && path === '/profile') {
      // 检测是否含有注入探针特征（单引号未闭合、报错函数等）
      const hasInjectProbe = /['"\\;]|extractvalue|updatexml|convert|cast|sleep|benchmark/i.test(storedName);
      let body;
      if (hasInjectProbe) {
        // 模拟 MySQL 报错页面（匹配 ERROR_SIG 的 "SQL syntax" 和 "mysql_fetch" 等）
        body = `<html><body><h1>Profile</h1><p>SQL syntax error: You have an error in your SQL syntax near '${storedName.replace(/</g, '&lt;')}' at line 1</p><!-- ts=${Date.now()} --></body></html>`;
      } else {
        // 正常页面（无报错特征）
        body = `<html><body><h1>Profile: ${storedName.replace(/</g, '&lt;')}</h1><p>Stored profile data.</p><!-- ts=${Date.now()} --></body></html>`;
      }
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end(body);
    }

    // GET /reset — 重置存储为默认值（测试间清理）
    if (req.method === 'GET' && path === '/reset') {
      storedName = 'alice';
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end('<h1>Reset OK</h1>');
    }

    res.writeHead(404, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end('<h1>404 not found (second-order-lab)</h1>');
  });

  return { server, stats, resetStats };
}

// 直接运行入口
if (process.argv[1] && import.meta.url === `file://${process.argv[1].replace(/\\/g, '/')}`) {
  const { server } = createSecondOrderLab();
  const PORT = Number(process.env.SO_LAB_PORT) || 8125;
  server.listen(PORT, '127.0.0.1', () => {
    console.log(`[second-order-lab] listening on http://127.0.0.1:${PORT}`);
    console.log('[second-order-lab] endpoints: POST /store?name=..., GET /profile, GET /reset');
  });
}
