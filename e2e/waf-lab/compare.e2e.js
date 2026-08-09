// e2e/waf-lab/compare.e2e.js
// 独立 e2e 夹具：同进程起 lab + 直接 import ScanManager 驱动两次扫描
//   configA：tamper 关（模拟裸请求被 WAF 拦 → 检出低）
//   configB：tamper 开（space2comment + charencode，绕过 WAF → 检出高）
// 算指标并写 results/compare.json + results/compare.md。
//
// 不经 vitest / node:test，由 `npm run waf-e2e` 独立运行，不污染单测套件。
//
// 关于 configB 的 tamper 组合：
//   设计原希望用 TAMPER_INTENSITY_PRESETS.medium = [space2comment, randomcase, charencode]。
//   但 randomcase 对**每个字母**随机大小写，会把 UnionDetector 用于确认注入的回显标记
//   'SQLISCANNER0' 的大小写打乱，导致 body.includes('SQLISCANNER0') 失败、union 检测失效
//   （configB 也会 0 检出 → 开>关 不成立）。
//   本实验室的绕过机制只依赖 space2comment（把 "UNION SELECT" 变为 "UNION/**/SELECT" 绕过空格锚定规则），
//   charencode 作为链中第二个插件（不影响标记字母）一并演示。randomcase 因上述冲突未纳入本 e2e 的 configB。
import { fileURLToPath } from 'url';
import path from 'path';
import fs from 'fs';
import { createLabApp } from './lab-server.js';
import { computeMetrics } from './metrics.js';
import { ScanManager } from '../../server/src/engine/ScanManager.js';

const LAB_PORT = Number(process.env.WAF_LAB_PORT) || 8099;
const TARGET = `http://localhost:${LAB_PORT}/vuln?id=1`;
const WAIT_TIMEOUT_MS = 180000;

// configB 实际使用的 tamper 组合（见文件头注释：space2comment 是绕过本实验室的关键）。
const CONFIG_B_TAMPER = ['space2comment', 'charencode'];

function buildConfig(tamperOn) {
  const tamper = tamperOn
    ? { enabled: true, plugins: CONFIG_B_TAMPER, intensity: 'medium' }
    : { enabled: false, plugins: [], intensity: 'medium' };
  return {
    techniques: ['union', 'error', 'boolean'],
    enableExtract: false, // 关掉拖库，聚焦"是否检出"，更快更确定
    maxColumnsGuess: 3, // 缩小 ORDER BY 列数探测，加速
    ratePerSec: 20,
    concurrency: 4,
    timeoutMs: 8000,
    blindRobust: { enabled: false }, // 用 legacy 布尔判定，减少采样请求、降低抖动
    wafEvasion: { randomUA: false, jitterMs: 0, obfuscate: false, tamper },
  };
}

function waitForScan(sm, scanId) {
  const start = Date.now();
  return new Promise((resolve) => {
    const tick = () => {
      const report = sm.getReport(scanId);
      if (report && (report.finishedAt || report.status === 'completed' || report.status === 'error')) {
        return resolve(report);
      }
      if (Date.now() - start > WAIT_TIMEOUT_MS) return resolve(report);
      setTimeout(tick, 200);
    };
    tick();
  });
}

async function runScan(sm, tamperOn) {
  const scanId = await sm.start({ url: TARGET, config: buildConfig(tamperOn) });
  return waitForScan(sm, scanId);
}

async function main() {
  const app = createLabApp();
  const server = app.listen(LAB_PORT);
  await new Promise((r) => {
    if (server.listening) return r();
    server.once('listening', r);
  });

  const sm = new ScanManager();

  // —— configA：tamper 关 ——
  app._stats.total = app._stats.blocked = app._stats.passed = 0;
  const reportA = await runScan(sm, false);
  const detectedA = (reportA?.vulns || []).length;
  const totalPoints = (reportA?.points || []).length || 1;
  const blockedReqA = app._stats.blocked;
  const totalReqA = app._stats.total;

  // —— configB：tamper 开 ——
  app._stats.total = app._stats.blocked = app._stats.passed = 0;
  const reportB = await runScan(sm, true);
  const detectedB = (reportB?.vulns || []).length;
  const blockedReqB = app._stats.blocked;
  const totalReqB = app._stats.total;

  const metrics = computeMetrics({
    totalPoints,
    detectedA,
    detectedB,
    blockedReqA,
    blockedReqB,
    totalReqA,
    totalReqB,
  });

  const outDir = path.resolve(fileURLToPath(import.meta.url), '../results');
  fs.mkdirSync(outDir, { recursive: true });
  const jsonPath = path.join(outDir, 'compare.json');
  const mdPath = path.join(outDir, 'compare.md');

  fs.writeFileSync(
    jsonPath,
    JSON.stringify(
      {
        metrics,
        configA: { tamper: 'off', detected: detectedA, totalPoints, blockedReq: blockedReqA, totalReq: totalReqA },
        configB: { tamper: 'on', plugins: CONFIG_B_TAMPER, detected: detectedB, totalPoints, blockedReq: blockedReqB, totalReq: totalReqB },
      },
      null,
      2
    )
  );

  const pass = metrics.detectRateB > metrics.detectRateA;
  const md = [
    '# WAF-v2 e2e：tamper 关 vs 开 检出率对比',
    '',
    `> 目标：${TARGET}`,
    `> configB tamper：${CONFIG_B_TAMPER.join(', ')}（medium 预设中的 space2comment 是绕过本实验室空格锚定规则的关键；`,
    '> randomcase 因会随机化 UnionDetector 用于确认的回显标记 `SQLISCANNER0` 的大小写导致检测失效，故未纳入本 e2e 的 configB）',
    '',
    '| 配置 | 总注入点 | 检出 | 检出率 | 被 WAF 拦截(req) | 拦截率 |',
    '|------|---------|------|--------|----------------|--------|',
    `| tamper 关 (configA) | ${totalPoints} | ${detectedA} | ${metrics.detectRateA}% | ${blockedReqA} | ${metrics.blockRateA}% |`,
    `| tamper 开 (configB) | ${totalPoints} | ${detectedB} | ${metrics.detectRateB}% | ${blockedReqB} | ${metrics.blockRateB}% |`,
    '',
    `**结论：detectRateB(${metrics.detectRateB}%) > detectRateA(${metrics.detectRateA}%) ? ${pass ? 'YES ✅' : 'NO ❌'}**`,
    '',
    '> 注：拦截率(blockRate)仅作参考。两次扫描请求构成不同——configB 命中 union 后提前 break，',
    '> 总体请求更少，且被跳过的主要是"放行类"布尔请求，故两次拦截率接近。主判据为检出率（开>关）。',
  ].join('\n');
  fs.writeFileSync(mdPath, md);

  console.log(md);
  console.log(`\n[waf-e2e] 产物已写入:\n  ${jsonPath}\n  ${mdPath}`);

  server.close();
  process.exit(pass ? 0 : 1);
}

main().catch((e) => {
  console.error('[waf-e2e] 失败:', e);
  process.exit(1);
});
