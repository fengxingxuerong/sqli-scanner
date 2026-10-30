// ============================================================================
// reproCheck.js —— 重放判定与可复现件落盘（D177）
//
// `reproPack.js` 负责「生成」；本文件负责「验证」：把每条 finding 的 PoC 请求
// 重放 N 次，判它到底属于哪种状态，并写成可交给第三方跑的脚本 + 期望值。
//
// 三种判定（互斥，直接进报告 `vuln.repro.status`）：
//   · reproduced  —— N 次重放的 status + body 哈希完全一致：**可复现的响应**
//                    （注意：这不等于「漏洞仍存在」，只是这条证据稳定）；
//   · single_hit  —— 重放结果不一致：证据不稳定，先排查会话失效 / 被拦 / 抖动；
//   · unreplayable —— 没有可重放的 PoC，或重放本身发不出去（网络/护栏/配置）。
// ============================================================================
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  normalizeForCompare,
  sameSample,
  buildReproScript,
  buildExpectJson,
  safeReproName,
} from './reproPack.js';

/**
 * 重放一条 finding 的 PoC，判定稳定性。
 * @param {object} vuln 漏洞条目（读 `poc.url/method/headers/body`）
 * @param {{request?: Function, repeats?: number, timeoutMs?: number, requestOpts?: object}} [opts]
 *   `request` 由调用方注入（单测用假通道；生产传 httpClient.request）
 * @returns {Promise<{status: 'reproduced'|'single_hit'|'unreplayable', consistent: boolean, samples: object[], reason?: string}>}
 *   判定结果（`samples` 为每次重放的归一化样本）
 */
export async function replayVuln(vuln, opts = {}) {
  const repeats = Math.max(2, Number(opts.repeats) || 2);
  const poc = vuln?.poc;
  if (!poc || !poc.url) return { status: 'unreplayable', consistent: false, samples: [], reason: '缺 PoC（没有 poc.url）' };
  if (typeof opts.request !== 'function') {
    return { status: 'unreplayable', consistent: false, samples: [], reason: '没有可用的重放通道' };
  }
  const samples = [];
  try {
    for (let i = 0; i < repeats; i++) {
      const res = await opts.request({
        url: poc.url,
        method: poc.method || 'GET',
        headers: poc.headers,
        body: poc.body,
        timeoutMs: opts.timeoutMs,
        retry: 0,
        ...(opts.requestOpts || {}),
      });
      samples.push(normalizeForCompare(res));
    }
  } catch (e) {
    return { status: 'unreplayable', consistent: false, samples, reason: String(e?.message || e) };
  }
  const consistent = samples.every((s) => sameSample(s, samples[0]));
  return { status: consistent ? 'reproduced' : 'single_hit', consistent, samples };
}

/**
 * 给报告里每条 finding 挂 `repro` 判定，并把汇总写进 `summary.repro`。
 * @param {object} report 引擎报告（原地修改 `vulns[i].repro` 与 `summary.repro`）
 * @param {{request?: Function, repeats?: number, timeoutMs?: number, requestOpts?: object}} [opts]
 * @returns {Promise<{repeats: number, checked: number, reproduced: number, singleHit: number, unreplayable: number}>}
 *   汇总计数
 */
export async function annotateRepro(report, opts = {}) {
  const repeats = Math.max(2, Number(opts.repeats) || 2);
  const vulns = Array.isArray(report?.vulns) ? report.vulns : [];
  const summary = { repeats, checked: 0, reproduced: 0, singleHit: 0, unreplayable: 0 };
  for (const v of vulns) {
    const r = await replayVuln(v, { ...opts, repeats });
    v.repro = {
      status: r.status,
      consistent: r.consistent,
      repeats,
      samples: r.samples,
      ...(r.reason ? { reason: r.reason } : {}),
    };
    summary.checked += 1;
    if (r.status === 'reproduced') summary.reproduced += 1;
    else if (r.status === 'single_hit') summary.singleHit += 1;
    else summary.unreplayable += 1;
  }
  report.summary = report.summary || {};
  report.summary.repro = summary;
  return summary;
}

/**
 * 把可复现件落盘：每条 finding 一份 `NN-<param>.sh` + `.expect.json`，外加索引。
 * @param {object} report 引擎报告（读 `vulns` 与 `summary.repro`）
 * @param {string} dir 目标目录（会递归创建）
 * @param {{repeats?: number, target?: string}} [ctx] 上下文
 * @returns {{dir: string, count: number}} 落盘目录与文件条数
 */
export function writeReproPack(report, dir, ctx = {}) {
  const vulns = Array.isArray(report?.vulns) ? report.vulns : [];
  mkdirSync(dir, { recursive: true });
  const lines = [
    '# 可复现件索引',
    '',
    `- 目标：\`${ctx.target || report?.target?.url || report?.url || '(见各条)'}\``,
    `- findings：${vulns.length} 条（重放判定见报告 \`vuln.repro\`）`,
    '',
    '> 每个 `.sh` 重放同一请求 N 次：结果一致 exit 0（CONSISTENT），不一致 exit 1（INCONSISTENT）。',
    '> **一致 ≠ 漏洞仍存在**，只说明这条证据稳定；不一致先排查会话失效 / 被拦 / 目标抖动。',
    '',
  ];
  vulns.forEach((v, i) => {
    const seq = String(i + 1).padStart(2, '0');
    const base = `repro-${seq}-${safeReproName(v?.param || v?.technique)}`;
    writeFileSync(join(dir, `${base}.sh`), buildReproScript(v, { repeats: ctx.repeats || 2 }), 'utf-8');
    writeFileSync(join(dir, `${base}.expect.json`), JSON.stringify(buildExpectJson(v, ctx), null, 2), 'utf-8');
    const st = v?.repro?.status || '未判定';
    lines.push(`${i + 1}. \`${base}.sh\` — ${v?.param || ''} · ${v?.technique || ''} · 判定：\`${st}\``);
  });
  writeFileSync(join(dir, 'README.md'), lines.join('\n') + '\n', 'utf-8');
  return { dir, count: vulns.length };
}
