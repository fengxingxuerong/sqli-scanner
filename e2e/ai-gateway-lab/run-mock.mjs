#!/usr/bin/env node
// ============================================================================
// e2e/ai-gateway-lab/run-mock.mjs —— [D276] AI 报告链路的确定性 CI 套件
//
// 为什么需要它：`run.mjs` 依赖真网关 + 真模型（opt-in，CI 里长期 SKIP）。AI 报告链路的
// 三角色流水线、分步 5 章撰写/审阅、D275 脱敏与确定性边界章节、usage/trace 累加，
// 在无真网关环境下没有可执行判据。本套件用 mock-gateway.mjs（行为模拟）跑**真实
// HTTP + 真实 ReportAI 代码**，断言链路事实：
//   · legacy 与 stepwise 两种模式都 exit 0（run.mjs 的既有判据逐字保留）；
//   · prompt 里不出现 fixture 的 host / 路径 / query 原值（脱敏）；
//   · 正文含 `<!-- engine-boundary -->` 与确定性边界章节（D275）；
//   · stepwise 每个短请求 ≤ STEPWISE_MAX_CHARS（1200），writer/reviewer 各 5 章；
//   · usage/trace 被逐请求累加（mock 返回 usage）。
//
// 诚实边界：
//   · 这是**行为模拟**，不证明模型输出质量/文风；真网关结论仍以 run.mjs 为准；
//   · 分类判据是 prompt 开头前缀：文案改了 ⇒ mock 返回 500 ⇒ 套件红（失败方向安全）；
//   · `--selftest` 自证判据有牙：构造泄漏必须被抓、缺边界章节必须被抓、
//     审阅角色返回空内容时 run.mjs 必须 exit 1（不把「没产出」记成通过）。
//
// 用法：
//   node e2e/ai-gateway-lab/run-mock.mjs
//   node e2e/ai-gateway-lab/run-mock.mjs --selftest
// ============================================================================
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { startMockGateway, classifyPrompt } from './mock-gateway.mjs';
import { FIXTURE_SECRETS } from './fixture.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '..', '..');
const RUN_MJS = path.join(HERE, 'run.mjs');
const BOUNDARY_MARKER = '<!-- engine-boundary -->';
const BOUNDARY_HEADING = '### 六、结论口径与覆盖边界';
const STEPWISE_MAX_CHARS = 1200;

/**
 * 跑一次 run.mjs（子进程），返回退出码与合并输出。
 * 必须用异步 spawn：mock 网关跑在本进程里，spawnSync 会阻塞事件循环 ⇒ 子进程
 * 连不上 mock（实测 ETIMEDOUT，零请求）。
 * @param {object} mock startMockGateway 句柄
 * @param {'legacy'|'stepwise'|'stepwise-concurrent'} mode 流水线模式
 * @returns {Promise<{status:number, out:string}>} 结果
 */
function runSuite(mock, mode) {
  const env = {
    ...process.env,
    AI_GATEWAY_URL: mock.url,
    AI_GATEWAY_MODEL: mock.model,
    AI_GATEWAY_TIMEOUT_MS: '30000',
    AI_GATEWAY_MAX_TOKENS: '2048',
    AI_GATEWAY_EXPECT_USAGE: '1',
    AI_REPORT_MASK: '1',
    AI_REPORT_SHORT_RETRY: '1',
    AI_REPORT_STEPWISE_MAX_CHARS: String(STEPWISE_MAX_CHARS),
  };
  if (mode.startsWith('stepwise')) {
    env.AI_REPORT_STEPWISE = '1';
    env.AI_REPORT_STEPWISE_CONCURRENCY = mode === 'stepwise-concurrent' ? '2' : '1';
  } else {
    delete env.AI_REPORT_STEPWISE;
    delete env.AI_REPORT_STEPWISE_CONCURRENCY;
  }
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [RUN_MJS], {
      cwd: ROOT,
      env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => { stdout += d; });
    child.stderr.on('data', (d) => { stderr += d; });
    const timer = setTimeout(() => { child.kill('SIGKILL'); }, 120000);
    child.on('close', (code) => {
      clearTimeout(timer);
      resolve({ status: code ?? 1, out: `${stdout}\n${stderr}` });
    });
    child.on('error', (e) => {
      clearTimeout(timer);
      resolve({ status: 1, out: `${stdout}\n${stderr}\nspawn error: ${e.message}` });
    });
  });
}

/**
 * 泄漏扫描：fixture 的 host / 路径 / query 原值不得出现在任何 prompt 里。
 * @param {string[]} prompts 所有请求的 system+user 文本
 * @returns {string[]} 问题列表（空 = 通过）
 */
function scanLeaks(prompts) {
  const hits = [];
  prompts.forEach((p, i) => {
    for (const secret of FIXTURE_SECRETS) {
      if (p.includes(secret)) hits.push(`请求#${i + 1} 含未脱敏片段「${secret}」`);
    }
  });
  return hits;
}

/**
 * 边界章节判据（D275）：marker + 标题必须同时出现（正文级，自证用）。
 * @param {string} text 正文
 * @returns {string[]} 问题列表（空 = 通过）
 */
function checkBoundaryContent(text) {
  const problems = [];
  if (!String(text).includes(BOUNDARY_MARKER)) problems.push(`正文缺 ${BOUNDARY_MARKER}`);
  if (!String(text).includes(BOUNDARY_HEADING)) problems.push(`正文缺「${BOUNDARY_HEADING}」`);
  return problems;
}

/**
 * 边界判据的**输出级**断言：run.mjs 只有在正文 marker/标题/verdict 全对时才打 marker=✅。
 * @param {string} out run.mjs 输出
 * @returns {string[]} 问题列表（空 = 通过）
 */
function checkBoundaryOutput(out) {
  const problems = [];
  if (!/结论口径：vulnerability_detected \/ 未验证面 1 类 \/ 未覆盖面 1 类 \/ marker=✅/.test(out)) {
    problems.push('run.mjs 未输出「结论口径：vulnerability_detected / 未验证面 1 类 / 未覆盖面 1 类 / marker=✅」');
  }
  return problems;
}

/**
 * 汇总请求分类计数。
 * @param {Array<{kind:string}>} requests mock 记录
 * @returns {Record<string, number>} kind → 次数
 */
function countKinds(requests) {
  /** @type {Record<string, number>} */
  const out = {};
  for (const r of requests) out[r.kind] = (out[r.kind] || 0) + 1;
  return out;
}

/**
 * 断言一次套件运行的链路事实。
 * @param {object} mock startMockGateway 句柄
 * @param {'legacy'|'stepwise'|'stepwise-concurrent'} mode 模式
 * @param {{status:number, out:string}} result runSuite 结果
 * @returns {string[]} 问题列表（空 = 通过）
 */
function checkRun(mock, mode, result) {
  const problems = [];
  if (result.status !== 0) problems.push(`${mode}: run.mjs exit=${result.status}\n${result.out}`);
  const requests = mock.state.requests;
  const prompts = requests.map((r) => `${r.system}\n${r.user}`);
  problems.push(...scanLeaks(prompts).map((h) => `${mode}: ${h}`));
  if (!prompts.some((p) => p.includes('<目标Host>'))) {
    problems.push(`${mode}: 未见脱敏占位符 <目标Host>（脱敏可能没生效）`);
  }
  problems.push(...checkBoundaryOutput(result.out).map((h) => `${mode}: ${h}`));
  const kinds = countKinds(requests);
  if (!kinds.analyst) problems.push(`${mode}: 没有 analyst 请求`);
  if (!kinds.writer) problems.push(`${mode}: 没有 writer 请求`);
  if (!kinds.reviewer) problems.push(`${mode}: 没有 reviewer 请求`);
  if (mode.startsWith('stepwise')) {
    if (kinds.writer < 5) problems.push(`${mode}: writer 请求 ${kinds.writer} < 5`);
    if (kinds.reviewer < 5) problems.push(`${mode}: reviewer 请求 ${kinds.reviewer} < 5`);
    const over = requests.filter((r) => r.userLen > STEPWISE_MAX_CHARS);
    if (over.length) {
      problems.push(`${mode}: ${over.length} 个请求超过 ${STEPWISE_MAX_CHARS} 字符：`
        + over.map((r) => `${r.kind}:${r.userLen}`).join(', '));
    }
    if (!/partial=false/.test(result.out)) problems.push(`${mode}: 输出未显示 partial=false`);
  }
  // [D277] 并发判据：默认（legacy/stepwise）必须串行；显式并发 2 必须真的重叠。
  const wantInFlight = mode === 'stepwise-concurrent' ? 2 : 1;
  if (mock.state.maxInFlight !== wantInFlight) {
    problems.push(`${mode}: 并发峰值 ${mock.state.maxInFlight} ≠ 期望 ${wantInFlight}`
      + `（默认串行 / 显式并发未生效都说明调度行为漂移）`);
  }
  if (!/结论口径：/.test(result.out)) problems.push(`${mode}: run.mjs 未输出结论口径行`);
  if (!/usage：total=\d+/.test(result.out)) problems.push(`${mode}: run.mjs 未输出 usage 行`);
  return problems;
}

/**
 * 打印一次套件的通过摘要（数字全部来自 mock 记录，不采信自报）。
 * @param {string} mode 模式
 * @param {object} mock mock 句柄
 * @returns {void}
 */
function printPass(mode, mock) {
  const requests = mock.state.requests;
  const kinds = countKinds(requests);
  const maxLen = Math.max(0, ...requests.map((r) => r.userLen));
  console.log(`  ✔ ${mode.padEnd(18)} 请求 ${String(requests.length).padStart(2)} `
    + `(analyst ${kinds.analyst || 0} / writer ${kinds.writer || 0} / reviewer ${kinds.reviewer || 0}) `
    + `最大 user prompt ${maxLen}B · 并发峰值 ${mock.state.maxInFlight} · 脱敏 0 泄漏 · 边界章节 ✅`);
}

/**
 * 自证：判据必须能红（构造样本 + 真实失败路径）。
 * @returns {Promise<void>}
 */
async function selftest() {
  const problems = [];
  // ① 泄漏扫描器：构造泄漏必须被抓，已脱敏样本不得误报
  const leaked = scanLeaks(['GET /vulnerabilities/sqli/?id=1&Submit=Submit HTTP/1.1']);
  if (leaked.length === 0) problems.push('泄漏扫描器对构造泄漏样本无反应（判据空转）');
  const clean = scanLeaks(['GET <目标Host>/***?id=***&Submit=*** HTTP/1.1']);
  if (clean.length) problems.push(`泄漏扫描器对已脱敏样本误报：${clean.join('；')}`);
  // ② 边界检查器：缺 marker / 缺标题都必须被抓
  if (checkBoundaryContent('普通正文').length === 0) problems.push('边界检查器对缺 marker 正文无反应');
  if (checkBoundaryContent(`${BOUNDARY_MARKER}\n正文`).length === 0) problems.push('边界检查器对缺标题正文无反应');
  if (checkBoundaryContent(`${BOUNDARY_MARKER}\n${BOUNDARY_HEADING}`).length) problems.push('边界检查器对完整样本误报');
  // ③ prompt 分类漂移：未知前缀必须按 500 处理（不能静默返回一段内容）
  const unknown = classifyPrompt('请帮我写一首诗');
  if (unknown.status !== 500 || unknown.kind !== 'unknown') {
    problems.push('未知 prompt 未按 500/unknown 处理（分类漂移会被静默放行）');
  }
  // ④ 真实失败路径：reviewer 返回空内容时，run.mjs 必须 exit 1 且如实标「未过审」
  const mock = await startMockGateway({ failRole: 'reviewer', failMode: 'empty' });
  try {
    const r = await runSuite(mock, 'legacy');
    if (r.status === 0) problems.push('reviewer 返回空内容时 run.mjs 仍 exit 0（判据无牙）');
    if (!/审阅角色校验：⚠️ 未过审/.test(r.out)) {
      problems.push('reviewer 空响应未被如实标注为「未过审」');
    }
  } finally {
    await mock.close();
  }
  if (problems.length) {
    console.error(`❌ run-mock selftest 有 ${problems.length} 项未通过：`);
    for (const p of problems) console.error(`  · ${p}`);
    process.exit(1);
  }
  console.log('✔ run-mock selftest 通过：泄漏/边界/分类/审阅失败四条判据均可返回 false');
}

/**
 * 主流程：legacy + stepwise 各跑一次。
 * @returns {Promise<void>}
 */
async function main() {
  if (process.argv.slice(2).includes('--selftest')) {
    await selftest();
    return;
  }
  const mock = await startMockGateway({ delayMs: 25 });
  try {
    console.log(`mock 网关：${mock.url}（模型 ${mock.model}，临时端口，每请求延迟 25ms 以暴露并发峰值）`);
    for (const mode of ['legacy', 'stepwise', 'stepwise-concurrent']) {
      mock.reset();
      const result = await runSuite(mock, mode);
      const problems = checkRun(mock, mode, result);
      if (problems.length) {
        console.error(`❌ ${mode} 模式判据未通过：`);
        for (const p of problems) console.error(`  · ${p}`);
        process.exit(1);
      }
      printPass(mode, mock);
    }
    console.log('AI 报告 mock 网关链路判据通过（legacy + stepwise 串行 + stepwise 并发 2）');
  } finally {
    await mock.close();
  }
}

await main();
