// 盲注统计判定 · 本地可复现演示
// 启动一个带网络抖动(随机噪声+微延迟)的本地靶机，用真实 HTTP 客户端跑 Boolean/Time 检测器，
// 演示 blindRobust 统计判定在抖动下仍能稳定识别注入、且不对纯噪声误报。
//
// 用法：
//   cd server && node scripts/blindRobustDemo.mjs
// 打真实目标：把 startTarget 返回的 baseUrl 换成你的真实 URL（确保已授权）。
import http from 'node:http';
import crypto from 'node:crypto';
import { BooleanBlindDetector } from '../src/engine/detectors/BooleanBlindDetector.js';
import { TimeBlindDetector } from '../src/engine/detectors/TimeBlindDetector.js';
import { defaults } from '../src/config/defaults.js';

// 本地抖动靶机：
//  - mode='vuln'：正常页含稳定标记 WELCOME；注入 AND 1=2 时变为 EMPTY（稳定信号），
//    但每次响应随机插入噪声注释 + 0~40ms 微延迟，模拟网络/动态内容抖动；SLEEP 真触发延迟。
//  - mode='noisy'：真/假都返回随机抖动的 WELCOME 变体，无任何稳定注入信号（应判定为"非注入"）。
const FILLER = 'x'.repeat(400); // 稳定填充：把尾部噪声压到总长 <15%，避免破坏前缀相似度（≥85% 才判相似）
function startTarget(mode) {
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      const u = new URL(req.url, 'http://x/');
      const q = u.searchParams.get('q') || '';
      const noise = `<!--${crypto.randomBytes(3).toString('hex')}-->`;
      const delay = Math.floor(Math.random() * 40); // 0~40ms 抖动

      // 仅 vuln 模式实现时间盲注：SLEEP/pg_sleep/WAITFOR 真触发延迟（noisy 模式不响应，避免假阳性）
      const sleepMatch = mode === 'vuln' ? q.match(/SLEEP\((\d+)\)|pg_sleep\((\d+)\)|WAITFOR DELAY '0:0:(\d+)'/) : null;
      if (sleepMatch) {
        const secs = Number(sleepMatch[1] || sleepMatch[2] || sleepMatch[3] || 2);
        setTimeout(() => {
          res.statusCode = 200;
          res.end('');
        }, secs * 1000);
        return;
      }

      let body;
      if (mode === 'vuln') {
        body = /1=2|'1'='2/.test(q)
          ? `<html><body><div id=res>EMPTY</div>${FILLER}${noise}</body></html>`
          : `<html><body><div id=res>WELCOME</div>${FILLER}${noise}</body></html>`;
      } else {
        // noisy：无稳定信号，仅随机抖动（WELCOME 后缀随机 hex，基线两两亦不相似 → 噪声地板高）
        body = `<html><body><div id=res>WELCOME${crypto.randomBytes(2).toString('hex')}</div>${FILLER}${noise}</body></html>`;
      }
      setTimeout(() => {
        res.statusCode = 200;
        res.end(body);
      }, delay);
    });
    server.listen(0, '127.0.0.1', () => resolve(server));
  });
}

// 真实 HTTP 客户端（contract 匹配 Detector.send：request({method,url,...}) -> {data,status}）
function makeHttpClient() {
  return {
    async request(opts) {
      const target = new URL(opts.url);
      const s0 = Date.now();
      const r = await new Promise((resolve, reject) => {
        http
          .get(target, (res) => {
            let body = '';
            res.on('data', (c) => (body += c));
            res.on('end', () => resolve({ data: body, status: res.statusCode }));
          })
          .on('error', reject);
      });
      return { ...r, elapsedMs: Date.now() - s0 };
    },
  };
}

function mkCtx(httpClient, baseUrl, rb) {
  return {
    httpClient,
    target: { method: 'GET', baseUrl, headerParams: {}, cookieParams: {}, config: {} },
    point: { id: 'p1', location: 'url', param: 'q', originalValue: '1', confirmed: false },
    dbms: 'MySQL',
    // 与引擎一致：先合并 defaults，再覆盖 blindRobust（默认已 enabled:true）
    config: { ...defaults, timeoutMs: 5000, timeThresholdMs: 800, blindRobust: { ...defaults.blindRobust, ...rb } },
  };
}

async function run() {
  for (const mode of ['vuln', 'noisy']) {
    const server = await startTarget(mode);
    const port = server.address().port;
    const baseUrl = `http://127.0.0.1:${port}/search?q=1`;
    const httpClient = makeHttpClient();
    console.log(`\n===== 靶机模式: ${mode} (${baseUrl}) =====`);

    const bd = new BooleanBlindDetector();
    const bRes = await bd.detect(mkCtx(httpClient, baseUrl, { enabled: true, adaptive: false }));
    console.log(`[Boolean] 固定门槛      -> vulnerable=${bRes.vulnerable} | ${bRes.evidence || '(无)'}`);

    const bdA = new BooleanBlindDetector();
    const bResA = await bdA.detect(mkCtx(httpClient, baseUrl, { enabled: true, adaptive: true }));
    console.log(`[Boolean] 自适应门槛    -> vulnerable=${bResA.vulnerable} | ${bResA.evidence || '(无)'}`);

    const bdL = new BooleanBlindDetector();
    const bResL = await bdL.detect(mkCtx(httpClient, baseUrl, { enabled: false }));
    console.log(`[Boolean] legacy 回退   -> vulnerable=${bResL.vulnerable} | ${bResL.evidence || '(无)'}`);

    const td = new TimeBlindDetector();
    const tRes = await td.detect(mkCtx(httpClient, baseUrl, { enabled: true, adaptive: true }));
    console.log(`[Time]    自适应门槛    -> vulnerable=${tRes.vulnerable} | ${tRes.evidence || '(无)'}`);

    server.close();
  }
  console.log('\n提示：把 baseUrl 换成真实目标即可在真靶上验证；默认 blindRobust.enabled 已为 true。');
  console.log('自适应看点：vuln 模式基线噪声低 → 门槛落回下限 0.66（严格）；noisy 模式基线噪声高 → 门槛抬到 cap 0.95（更难误报）。');
}

run().catch((e) => {
  console.error(e);
  process.exit(1);
});
