// ============================================================================
// e2e/param-name-lab/run.mjs —— [D93] 参数名注入真靶场判据（[D103] 扩 JSON body 键名）
//
// 判据（读引擎报告的事实字段，不看套件自报）：
//   ① /colfilter（query 键名拼 SQL）开启 testParamNames 后**必须检出**，且命中点 location='paramName'
//   ② /colfilter-safe（同写法 + 白名单）**必须零检出**（证明不是「见 query 就报」）
//   ③ 关闭 testParamNames 时 /colfilter **不应检出**（证明能力的开关语义真实存在，
//      而不是既有通道的漏光）
//   [D103] ④-⑥ 同三条扩到 POST /colfilter-json（**JSON body 键名**载体：布尔载荷进键名，
//      值参数化；安全白名单 /colfilter-json-safe 零检出 + 开关关闭对照）
//   [D105] ⑦-⑨ 同三条再扩到 POST /colfilter-xml（**XML body 元素名**载体：NameChar 不允许
//      空格/引号 ⇒ 布尔载荷承载不了，判据是算术位移探针 tag-0/tag-1；安全白名单
//      /colfilter-xml-safe 零检出 + 开关关闭对照）
//   [D106] ⑩-⑫ 再扩到 GET /colsort（**ORDER BY 固定后缀**形态 `ORDER BY ${k} DESC`：布尔载荷
//      退化为常量排序、UNION 语法不可表达 ⇒ 序数差分 `{k}, 1-- -` / `{k}, 9999-- -`；
//      安全白名单 /colsort-safe 零检出 + 开关关闭对照）
//
// 环境：需 MySQL + 靶场（D95 起靶场自带幂等夹具：自建 paramname_lab + 种子，可连即可跑）。
// 未就绪输出 [SKIP] 并 exit 0（acceptance 读文本判据，不看退出码）。
//
// 用法：node e2e/param-name-lab/run.mjs
// ============================================================================

import { spawn } from 'node:child_process';
import net from 'node:net';
import { fileURLToPath } from 'node:url';
import { ScanManager } from '../../server/src/engine/ScanManager.js';

const PORT = Number(process.env.PARAMNAME_LAB_PORT || 8123);
const BASE = `http://127.0.0.1:${PORT}`;
const MAX_MS = Number(process.env.PARAMNAME_LAB_TIMEOUT_MS) || 120000;

const portOpen = (port) => new Promise((resolve) => {
  const s = net.connect(port, '127.0.0.1');
  s.on('connect', () => { s.end(); resolve(true); });
  s.on('error', () => { s.destroy(); resolve(false); });
});

/** 扫一个端点，返回 { verdict, vulns, reqs }（ScanManager.start + 轮询终态，与 juice-shop-lab 同范式） */
async function scan(path, testParamNames, opts = {}) {
  const mgr = new ScanManager({});
  const cfg = {
    concurrency: 1,
    ratePerSec: 0,
    retry: 0,
    timeoutMs: 8000,
    techniques: ['union', 'boolean', 'error'],
    enableExtract: false,
    level: 1,
    risk: 2,
    productionMode: false,
    testParamNames,
  };
  const id = await mgr.start({
    url: `${BASE}${path}`,
    config: cfg,
    ...(opts.method ? { method: opts.method } : {}),
    ...(opts.jsonBody ? { jsonBody: opts.jsonBody } : {}),
    ...(opts.xmlBody ? { xmlBody: opts.xmlBody } : {}),
  });
  const t0 = Date.now();
  for (;;) {
    const st = mgr.scans.get(id);
    if (st && (st.status === 'completed' || st.status === 'error')) {
      const report = mgr.getReport(id) || {};
      return {
        verdict: report?.summary?.verdict ?? null,
        vulns: Array.isArray(report?.vulns) ? report.vulns : [],
        reqs: report?.summary?.validity?.counts?.total ?? 0,
      };
    }
    if (Date.now() - t0 > MAX_MS) {
      mgr.stop(id);
      throw new Error('scenario timeout');
    }
    await new Promise((r) => setTimeout(r, 200));
  }
}

async function withLab(body) {
  if (await portOpen(PORT)) return body(false);
  const proc = spawn(process.execPath, [fileURLToPath(new URL('./lab.mjs', import.meta.url))], {
    cwd: fileURLToPath(new URL('../..', import.meta.url)),
    stdio: 'ignore',
  });
  for (let i = 0; i < 30; i++) {
    if (await portOpen(PORT)) break;
    await new Promise((r) => setTimeout(r, 500));
  }
  try {
    if (!(await portOpen(PORT))) return { skip: '靶场未能启动（端口 8123 未就绪）' };
    return await body(true);
  } finally {
    try { proc.kill(); } catch { /* 已退出 */ }
  }
}

const timeout = (p) => Promise.race([p, new Promise((_, rej) => setTimeout(() => rej(new Error('scenario timeout')), MAX_MS))]);

const main = async () => {
  const skipOr = async (fn) => fn();
  const out = await skipOr(() => withLab(async () => {
    // 先探测 MySQL 是否可用（靶场起了但库不在 ⇒ 所有请求 query failed ⇒ 结论无意义）。
    // ⚠ 判据不能用「响应里有没有 sql=」——错误页也回显 sql=（D95 实测：MySQL 未起时
    // 该判据把 [SKIP] 骗成「就绪」，三路扫描全 0 ⇒ 假 [FAIL]）。
    const probe = await fetch(`${BASE}/colfilter?name=Keyboard`).then((r) => r.text()).catch(() => '');
    if (!/sql=/.test(probe) || /query failed/.test(probe)) return { skip: '靶场探针失败（MySQL 未就绪？）' };

    const on = await timeout(scan('/colfilter?name=Keyboard', true));
    const off = await timeout(scan('/colfilter?name=Keyboard', false));
    const safe = await timeout(scan('/colfilter-safe?name=Keyboard', true));
    // [D103] JSON body 键名载体三条（与 query 三条同型）
    const jbody = { name: 'Keyboard' };
    const jsonOn = await timeout(scan('/colfilter-json', true, { method: 'POST', jsonBody: jbody }));
    const jsonOff = await timeout(scan('/colfilter-json', false, { method: 'POST', jsonBody: jbody }));
    const jsonSafe = await timeout(scan('/colfilter-json-safe', true, { method: 'POST', jsonBody: jbody }));
    // [D105] XML body 元素名载体三条（数值语境列 price —— 位移探针的适用形态）
    const xbody = '<?xml version="1.0" encoding="UTF-8"?><filter><price>499</price></filter>';
    const xmlOn = await timeout(scan('/colfilter-xml', true, { method: 'POST', xmlBody: xbody }));
    const xmlOff = await timeout(scan('/colfilter-xml', false, { method: 'POST', xmlBody: xbody }));
    const xmlSafe = await timeout(scan('/colfilter-xml-safe', true, { method: 'POST', xmlBody: xbody }));
    // [D106] ORDER BY 固定后缀形态三条（键名拼进 ORDER BY 位置且后跟固定「 DESC」）
    const sortOn = await timeout(scan('/colsort?price=1', true));
    const sortOff = await timeout(scan('/colsort?price=1', false));
    const sortSafe = await timeout(scan('/colsort-safe?price=1', true));

    const paramHits = on.vulns.filter((v) => v.location === 'paramName').length;
    const jsonHits = jsonOn.vulns.filter((v) => v.location === 'paramName').length;
    const xmlHits = xmlOn.vulns.filter((v) => v.location === 'paramName').length;
    const sortHits = sortOn.vulns.filter((v) => v.location === 'paramName').length;
    const facts = {
      vuln检出: `${on.vulns.length}`,
      'vuln中paramName点': `${paramHits}`,
      开关关闭: `${off.vulns.length}`,
      安全点检出: `${safe.vulns.length}`,
      json检出: `${jsonOn.vulns.length}`,
      'json中paramName点': `${jsonHits}`,
      json开关关闭: `${jsonOff.vulns.length}`,
      json安全点检出: `${jsonSafe.vulns.length}`,
      xml检出: `${xmlOn.vulns.length}`,
      'xml中paramName点': `${xmlHits}`,
      xml开关关闭: `${xmlOff.vulns.length}`,
      xml安全点检出: `${xmlSafe.vulns.length}`,
      sort检出: `${sortOn.vulns.length}`,
      'sort中paramName点': `${sortHits}`,
      sort开关关闭: `${sortOff.vulns.length}`,
      sort安全点检出: `${sortSafe.vulns.length}`,
    };
    const pass = on.vulns.length > 0 && paramHits > 0 && off.vulns.length === 0 && safe.vulns.length === 0
      && jsonHits > 0 && jsonOff.vulns.length === 0 && jsonSafe.vulns.length === 0
      && xmlHits > 0 && xmlOff.vulns.length === 0 && xmlSafe.vulns.length === 0
      && sortHits > 0 && sortOff.vulns.length === 0 && sortSafe.vulns.length === 0;
    return { facts, pass, verdict: on.verdict };
  }));

  if (out?.skip) {
    console.log(`[SKIP] 参数名注入靶场：${out.skip}`);
    process.exit(0);
  }
  const f = out.facts || {};
  console.log(`[param-name] vuln=${f.vuln检出} paramNameHit=${f['vuln中paramName点']} off=${f.开关关闭} safe=${f.安全点检出}`);
  console.log(`[param-name] jsonVuln=${f.json检出} jsonParamNameHit=${f['json中paramName点']} jsonOff=${f.json开关关闭} jsonSafe=${f.json安全点检出}`);
  console.log(`[param-name] xmlVuln=${f.xml检出} xmlParamNameHit=${f['xml中paramName点']} xmlOff=${f.xml开关关闭} xmlSafe=${f.xml安全点检出}`);
  console.log(`[param-name] sortVuln=${f.sort检出} sortParamNameHit=${f['sort中paramName点']} sortOff=${f.sort开关关闭} sortSafe=${f.sort安全点检出}`);
  console.log(out.pass ? '[PASS] 参数名注入（D93+D103+D105+D106）' : '[FAIL] 参数名注入（D93+D103+D105+D106）');
  process.exit(out.pass ? 0 : 1);
};

main().catch((e) => {
  console.error('[param-name] 运行失败：', e && e.message);
  process.exit(1);
});
