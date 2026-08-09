// e2e/waf-lab/lab-server.js
// 本地 mock-WAF 实验室：Express 中间件复刻 ModSecurity CRS 类"签名拦截"，
// 命中任一 SQLi 签名即 403；否则放行至后端 sqli-labs 风格注入点 /vuln。
//
// 复用既有 express（位于 server/node_modules）。本文件处于 e2e/waf-lab/，
// 从根目录向上解析不到 express，故用 createRequire 直接指向 server/node_modules/express，
// 其传递依赖仍可据此目录向上解析，满足"无新增 npm 依赖"约束。
import { createRequire } from 'module';
import { WAF_SIGNATURES } from './waf-signatures.js';

const require = createRequire(import.meta.url);
const express = require('../../server/node_modules/express');

/**
 * 创建实验室 Express 应用（工厂，便于 e2e 同进程复用）。
 * @returns {import('express').Express} 带 _stats 的 app
 */
export function createLabApp() {
  const app = express();
  const stats = { total: 0, blocked: 0, passed: 0 };

  // WAF 中间件：对 query/body 命中任一 SQLi 签名即 403（复刻拦截）；否则放行。
  app.use((req, res, next) => {
    const probe = JSON.stringify(req.query) + JSON.stringify(req.body || '');
    stats.total += 1;
    const hit = WAF_SIGNATURES.some((s) => s.re.test(probe));
    if (hit) {
      stats.blocked += 1;
      return res.status(403).send('<h1>403 Forbidden</h1>');
    }
    stats.passed += 1;
    next();
  });

  // 良性基线页（供指纹/基线抓取，应放行）。
  app.get('/benign', (_q, r) => r.send('<html><body>ok</body></html>'));

  // sqli-labs 风格注入点：直接回显 id。
  // 这样当绕过 WAF 的请求（含 UNION 回显标记 SQLISCANNER0..）到达时，
  // 扫描器的 UnionDetector 能在响应中找到标记 → 触发 union 检测。
  // 关键：不在这里做真假/报错分支，避免污染"开 vs 关"的对照口径。
  app.get('/vuln', (req, r) => {
    const id = String(req.query.id ?? '1');
    r.send(`row:${id}`);
  });

  // 统计与重置端点（供 e2e / 手动验证读取）。
  app.get('/__stats', (_q, r) => r.json(stats));
  app.post('/__reset', (_q, r) => {
    stats.total = 0;
    stats.blocked = 0;
    stats.passed = 0;
    r.json({ ok: true });
  });

  // 把 stats 挂到 app 上，便于 e2e 同进程直接读取（避免 HTTP 自读导致计数 +1）。
  app._stats = stats;
  return app;
}

// 直接运行入口：node e2e/waf-lab/lab-server.js（npm run waf-lab）
if (import.meta.url === `file://${process.argv[1]}`) {
  const port = Number(process.env.WAF_LAB_PORT) || 8099;
  createLabApp().listen(port, () => {
    console.log(`[waf-lab] http://localhost:${port}  (命中 SQLi 签名 → 403；/benign、/vuln?id=1 放行)`);
  });
}
