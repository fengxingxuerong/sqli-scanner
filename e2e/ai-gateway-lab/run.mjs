#!/usr/bin/env node
// ============================================================================
// ai-gateway-lab/run.mjs —— [D228 2026-11-01] AI 报告网关端到端验收（套件 ai-gateway）
//
// 为什么需要它：AI_REPORT 三角色流水线此前只有 stub 单测（server/tests/aiReportCli.test.js），
// 「本地网关 × 真报告」全链路（HTTP 实调 → analyst→writer→reviewer → 脱敏 → 审阅标记 →
// 元数据头 → 落盘）从未进过验收门禁。本套件用**真实 HTTP 网关**跑完 ReportAI 全流水线，
// 再对 ai-report.md 的产物事实做断言。
//
// 诚实边界：
//   · 网关/模型未就绪 → `[SKIP] AI 网关不可用：…` + exit 0（未就绪不是失败，但必须写明原因，
//     不得冒充通过 —— 与 vampi/juice 套件的 SKIP 口径一致）；
//   · 断言的是「链路事实」（网关实调回声 / 脱敏 / 审阅标记 / 元数据头 / 落盘字节数 /
//     D275 确定性边界章节），**不判报告文风质量** —— 0.5B 级链路验证模型输出极短是预期，
//     不构成套件失败；
//   · 默认探 Ollama(127.0.0.1:11434)；自建 OpenAI 兼容网关（如 dsh:8326）用
//     AI_GATEWAY_URL / AI_GATEWAY_KEY / AI_GATEWAY_MODEL 注入。
//   · [D276] 无真网关时用 run-mock.mjs（确定性 mock 网关）跑同一份判据；本文件的边界
//     章节断言对真网关同样成立（章节由引擎追加，不是模型生成）。
// ============================================================================

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { makeReport } from './fixture.mjs';

const GATEWAY_URL = process.env.AI_GATEWAY_URL || 'http://127.0.0.1:11434';
// [D254] 可选备用网关：三个角色/降级路径分到不同端点，429 时真换网关而非原地等 60s
const GATEWAY_URL_2 = process.env.AI_GATEWAY_URL_2 || '';
const GATEWAY_MODEL = process.env.AI_GATEWAY_MODEL || 'qwen2.5:0.5b';
const GATEWAY_KEY = process.env.AI_GATEWAY_KEY || 'local';
const GATEWAY_KEY_2 = process.env.AI_GATEWAY_KEY_2 || GATEWAY_KEY;
const TIMEOUT_MS = Number(process.env.AI_GATEWAY_TIMEOUT_MS) || 420000; // 3 角色均分（140s/角色）：全量验收负载下 0.5B CPU 推理需余量
// 推理模型（glm-5.3-flash 带 reasoning_content）生成 8192 tokens 会拖过 per-step 超时；
// 验收套件按本地网关调小，生产默认 8192 不变。两者都可用 env 覆盖。
const MAX_TOKENS = process.env.AI_GATEWAY_MAX_TOKENS || '2048';
const RATE_COOLDOWN_MS = process.env.AI_GATEWAY_429_COOLDOWN_MS || '3000';
// [D259] 分步短 prompt 为 opt-in（AI_REPORT_STEPWISE=1）；未开启时本套件判据零变化。
const STEPWISE = process.env.AI_REPORT_STEPWISE === '1';

function skip(reason) {
  console.log(`[SKIP] AI 网关不可用：${reason}`);
  process.exit(0);
}

/**
 * 网关探活（真实 HTTP，非 stub）。失败抛带原因的 Error，由 main 转 SKIP。
 * @param {string} url 网关根地址（不带 /v1）
 * @param {string} key 该网关的 API key
 * @returns {Promise<string[]>} /v1/models 返回的模型 id 列表
 */
async function probeModels(url, key) {
  let r;
  try {
    r = await fetch(`${url}/v1/models`, { headers: { Authorization: `Bearer ${key}` } });
  } catch (e) {
    throw new Error(`/v1/models 不可达（${e.message}）`, { cause: e });
  }
  if (!r.ok) throw new Error(`/v1/models -> HTTP ${r.status}`);
  const j = await r.json();
  return (j?.data || []).map((m) => m.id);
}

async function main() {
  // ① 网关探活 + 模型就绪（真实 HTTP，非 stub）
  let ids;
  try {
    ids = await probeModels(GATEWAY_URL, GATEWAY_KEY);
  } catch (e) {
    skip(e.message);
  }
  if (!ids.includes(GATEWAY_MODEL)) {
    skip(`模型 ${GATEWAY_MODEL} 未就绪（现有：${ids.slice(0, 5).join(', ') || '空'}）`);
  }
  if (GATEWAY_URL_2) {
    let ids2;
    try {
      ids2 = await probeModels(GATEWAY_URL_2, GATEWAY_KEY_2);
    } catch (e) {
      skip(`备用网关 ${GATEWAY_URL_2}：${e.message}`);
    }
    if (!ids2.includes(GATEWAY_MODEL)) {
      skip(`备用网关模型 ${GATEWAY_MODEL} 未就绪（现有：${ids2.slice(0, 5).join(', ') || '空'}）`);
    }
  }

  // ② 注入 ReportAI 环境（必须在 import 之前：ReportAI 在模块加载时读取 env）
  // [D254] key↔端点配对：analyst→主网关、writer→备用网关、reviewer→主网关；
  // 429 降级会跳过冷却 key 选到**另一个端点**，不再是同一网关原地等 60s。
  const base1 = `${GATEWAY_URL}/v1/chat/completions`;
  const base2 = `${GATEWAY_URL_2 || GATEWAY_URL}/v1/chat/completions`;
  process.env.AI_REPORT_API_BASE = base1;
  process.env.AI_REPORT_API_BASE_2 = base2;
  process.env.AI_REPORT_API_BASE_3 = base1;
  process.env.AI_REPORT_KEY_1 = GATEWAY_KEY;
  process.env.AI_REPORT_KEY_2 = GATEWAY_KEY_2;
  process.env.AI_REPORT_KEY_3 = GATEWAY_KEY;
  process.env.AI_REPORT_MODEL_1 = GATEWAY_MODEL;
  process.env.AI_REPORT_MODEL_2 = GATEWAY_MODEL;
  process.env.AI_REPORT_MODEL_3 = GATEWAY_MODEL;
  process.env.AI_REPORT_MAX_TOKENS = MAX_TOKENS;
  process.env.AI_REPORT_429_COOLDOWN_MS = RATE_COOLDOWN_MS;
  const { generateAiReport } = await import('../../server/src/services/ReportAI.js');
  const { writeAiReportFiles } = await import('../../server/src/services/aiReportCli.js');

  // ③ 最小真形态 fixture：字段 = ReportAI 消费面（target/points/vulns 的
  //    poc_payload / poc_verify / evidence）+ D275 边界事实（summary.*）。
  //    scanId 每次变化，防 reportFingerprint 缓存命中（命中会让「网关实调」事实失真）。
  //    [D276] fixture 外移到 fixture.mjs：run-mock 的泄漏词表与它同源，避免两份漂移。
  const report = makeReport();

  // ④ 全流水线（真实 HTTP；三角色均空响应时 generateAiReport 会抛错）
  const t0 = Date.now();
  let result;
  try {
    result = await generateAiReport(report, TIMEOUT_MS);
  } catch (e) {
    console.error(`❌ AI 网关判据未通过：流水线失败（${e.message}）`);
    process.exit(1);
  }
  const elapsedMs = Date.now() - t0;

  // ⑤ 落盘到系统临时目录（不在仓库留产物），核对 ai-report.md 元数据头
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ai-gateway-lab-'));
  const { file, bytes } = writeAiReportFiles(dir, result, report, { elapsedMs, masked: true });
  const md = fs.readFileSync(file, 'utf8');
  const markers = [
    md.includes('generated by sqli-scanner --ai-report'),
    /source report:\s*\S/.test(md),
    md.includes('pipeline: analyst→writer→reviewer'),
    md.includes('数据脱敏'),
  ];
  const metaCount = markers.filter(Boolean).length;
  const masked = /数据脱敏[:：]\s*开启/.test(md); // 确定性证据：头部策略行（meta.masked 由 runner 固定置 true）
  // 注：正文是否回显 <目标Host>//*** 占位符取决于模型（0.5B 非确定输出），不作断言 —— 见套件边界注释
  const reviewed = String(result.reviewNote || '').includes('✅');
  const modelChain = `${GATEWAY_MODEL}→${GATEWAY_MODEL}→${GATEWAY_MODEL}`;
  const realCall = result.success === true && result.model === modelChain;
  // [D276] D275 确定性边界章节：引擎追加，不依赖模型是否照做。
  const boundary = result.boundary || {};
  const boundaryMarker = String(result.content || '').includes('<!-- engine-boundary -->');
  const boundaryHeading = String(result.content || '').includes('### 六、结论口径与覆盖边界');
  const boundaryVerdict = boundary.verdict === 'vulnerability_detected';
  const boundaryOk = boundaryMarker && boundaryHeading && boundaryVerdict
    && boundary.unverifiedSurfaces?.length === 1 && boundary.uncoveredSurfaces?.length === 1;
  // [D276] usage/trace 只在显式要求时断言（真网关可能不返回 usage，不能把缺字段判成失败）。
  const expectUsage = process.env.AI_GATEWAY_EXPECT_USAGE === '1';
  const usageOk = !expectUsage || (
    Number(result.usage?.total_tokens) > 0 && Array.isArray(result.trace) && result.trace.length >= 3
  );

  const gateways = [GATEWAY_URL, GATEWAY_URL_2].filter(Boolean).join(' + ');
  console.log(`网关：${gateways}（模型 ${GATEWAY_MODEL}, max_tokens=${MAX_TOKENS}）`);
  console.log(`审阅角色校验：${reviewed ? '✅' : '⚠️ 未过审'}`);
  console.log(`元数据头：${metaCount}/4`);
  console.log(`数据脱敏：${masked ? 'on' : 'off'}`);
  console.log(`落盘：true (${Buffer.byteLength(md, 'utf8')} bytes, 内容 ${bytes}B)`);
  console.log(`网关实调：${realCall ? 'true' : 'false'} (${result.model || 'n/a'})`);
  console.log(`结论口径：${boundary.verdict || 'missing'} / 未验证面 ${boundary.unverifiedSurfaces?.length ?? 'NA'} 类 / 未覆盖面 ${boundary.uncoveredSurfaces?.length ?? 'NA'} 类 / marker=${boundaryMarker && boundaryHeading ? '✅' : '❌'}`);
  console.log(`usage：total=${result.usage?.total_tokens ?? 'NA'} tokens（trace ${result.trace?.length ?? 0} 请求）`);
  console.log(`耗时：${elapsedMs}ms`);
  // [D259] 分步模式专属判据（加严，不放宽原有任何一条）：所有短章节都成功产出并逐章审阅，
  // 且不回退到整篇长流水线。非分步模式恒 true，原判据逐字不变。
  const sw = result.stepwise;
  const stepwiseOk = !STEPWISE || (
    sw?.enabled === true && sw.partial === false && sw.fallback === null
    && Number(sw.writerSteps) > 1 && sw.failedSteps?.length === 0
  );
  if (STEPWISE) {
    console.log(`分步短 prompt：on（writer ${sw?.writerSteps ?? 'NA'} 章 / 审阅 ${sw?.reviewedSections ?? 'NA'} 章 / 并发 ${sw?.concurrency ?? 'NA'} / partial=${String(sw?.partial)} / fallback=${sw?.fallback ?? 'none'}）`);
  }

  const pass = reviewed && metaCount === 4 && masked && realCall && bytes > 0 && stepwiseOk
    && boundaryOk && usageOk;
  if (!pass) {
    console.error('❌ AI 网关判据未通过（见上方事实数字）');
    process.exit(1);
  }
  console.log('AI 网关判据通过');
}

await main();
