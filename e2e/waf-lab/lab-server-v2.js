// e2e/waf-lab/lab-server-v2.js
// WAF 实验室 v2：支持 3 个 WAF profile，可切换

import { createRequire } from 'module';
import { PROFILES, MODSECURITY_CRS } from './waf-profiles.js';

const require = createRequire(import.meta.url);
const express = require('../../server/node_modules/express');

/**
 * 创建 WAF 实验室应用（带 profile 切换）
 * @param {string} profileId - 'modsecurity_crs' | 'cloudflare_waf' | 'all_in_one'
 */
export function createLabApp(profileId = 'modsecurity_crs') {
  const app = express();
  let currentProfile = PROFILES.find(p => p.id === profileId) || MODSECURITY_CRS;
  const stats = { total: 0, blocked: 0, passed: 0 };
  const tls = { blocked: {}, passed: {} }; // 按规则 ID 统计

  // 获取当前 profile 的规则函数
  function getRules() { return currentProfile.rules; }

  // WAF 中间件
  app.use((req, res, next) => {
    if (req.path.startsWith('/__')) return next(); // 管理端点放行
    const probe = JSON.stringify(req.query) + JSON.stringify(req.body || '');
    stats.total += 1;
    const rules = getRules();
    const hit = rules.find((r) => r.re.test(probe));
    if (hit) {
      stats.blocked += 1;
      tls.blocked[hit.id] = (tls.blocked[hit.id] || 0) + 1;
      return res.status(403).send(`<h1>403 Forbidden</h1><p>Rule: ${hit.id}</p>`);
    }
    stats.passed += 1;
    tls.passed[hit?.id || 'none'] = (tls.passed['none'] || 0) + 1;
    next();
  });

  // 良性基线页
  app.get('/benign', (_q, r) => r.send('<html><body>ok</body></html>'));

  // 注入点
  //
  // ⚠️ 注意：本端点**不是真实注入点**（2026-09-18 查明）。
  //   实现只是 `row:${id}` 字符串拼接回显，没有任何 SQL 执行 ——
  //   加 `'` 不报错、`order by` 无差异、union 回显标记永不出现。
  //   历史注释曾写「放行至后端 sqli-labs 风格注入点」，但**后端从未实现**。
  //   依赖本端点的 A/B 判据（compare.e2e.js）因此恒失败，请改用真靶场：
  //   e2e/waf-lab/compare-real.e2e.mjs（复用 real-mysql-lab 的真注入点）。
  //   保留本端点仅为兼容既有可视化/统计调试，勿用于验证检测能力。
  app.get('/vuln', (req, r) => {
    const id = String(req.query.id ?? '1');
    r.send(`row:${id}`);
  });

  // 管理端点
  app.get('/__stats', (_q, r) => r.json({ stats, tls, profile: currentProfile.id }));
  app.post('/__reset', (_q, r) => {
    stats.total = 0; stats.blocked = 0; stats.passed = 0;
    Object.keys(tls.blocked).forEach(k => delete tls.blocked[k]);
    Object.keys(tls.passed).forEach(k => delete tls.passed[k]);
    r.json({ ok: true });
  });
  app.post('/__profile', (req, r) => {
    const pid = req.query.id || req.body?.profile;
    const p = PROFILES.find(x => x.id === pid);
    if (!p) return r.status(400).json({ error: `未知 profile: ${pid}，可选: ${PROFILES.map(x => x.id).join(', ')}` });
    currentProfile = p;
    r.json({ ok: true, profile: currentProfile.id, rules: currentProfile.rules.length });
  });

  app._stats = stats;
  app._tls = tls;
  return app;
}

// 直接运行入口
if (import.meta.url === `file://${process.argv[1]}`) {
  const port = Number(process.env.WAF_LAB_PORT) || 8099;
  // [⑲] 默认 profile 改为 all_in_one（与 package.json waf-lab-v2 script 意图一致），
  // 消除 POSIX 内联环境变量 WAF_PROFILE=all_in_one 在 Windows 上的不可移植问题；
  // 仍可通过 WAF_PROFILE 环境变量覆盖
  const profile = process.env.WAF_PROFILE || 'all_in_one';
  createLabApp(profile).listen(port, () => {
    console.log(`[waf-lab-v2] http://localhost:${port}  profile=${profile}`);
    console.log(`  可用 profile: ${PROFILES.map(p => p.id).join(', ')}`);
    console.log(`  切换: POST /__profile?id=all_in_one`);
  });
}