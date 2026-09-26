// ============================================================================
// modsec-target.mjs —— 真机 WAF 对拍用的**最小靶站后端**
//
// 存在的理由：ModSecurity 容器是反代，必须有个上游。CI 里它要比容器先起来
// （nginx 启动时上游不在会有概率直接退出），所以拆成独立进程由 workflow 后台拉起。
//
// 刻意不用真 MySQL：本轮测的是「WAF 放不放行」，不是「注入能不能打穿数据库」。
// 少一个 MySQL 依赖就少一类 ECONNREFUSED 假失败 —— 本仓 waf-lab 那条链在 CI 上
// 正是栽在「依赖真库但环境里没起库」上（失败现场还被记成了产品 FAIL）。
// ============================================================================
import { createServer } from 'node:http';

const PORT = Number(process.env.MODSEC_TARGET_PORT || 8151);

createServer((req, res) => {
  const u = new URL(req.url, 'http://x');
  res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' });
  res.end(`OK id=${u.searchParams.get('id') ?? ''}`);
}).listen(PORT, '127.0.0.1', () => {
  console.log(`modsec-target: echo backend on 127.0.0.1:${PORT}`);
});
