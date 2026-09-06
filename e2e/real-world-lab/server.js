// e2e/real-world-lab/server.js —— 直接运行入口
// node e2e/real-world-lab/server.js [--waf=modsecurity_crs] [--port=8130]
import { createRealLabApp } from './lab-app.js';

const port = Number(process.env.REAL_LAB_PORT) || 8130;
const waf = process.env.REAL_LAB_WAF || null;
const app = await createRealLabApp({ waf: waf || undefined });
app.listen(port, () => {
  console.log(`[real-world-lab] http://127.0.0.1:${port}  db=${app._stats.ver}  waf=${waf || 'off'}`);
});