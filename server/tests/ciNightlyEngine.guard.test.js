// ============================================================================
// ciNightlyEngine.guard.test.js —— 「真引擎对拍」不许退化成周度（也不许被 continue-on-error 吞）
//
// 背景（2026-09-27 全栈审计）：对外 WAF 命中率数字的**唯一外部裁判**是 `modsec-live`
// （真 ModSecurity + 真 CRS 镜像对拍）。自实现的 `e2e/waf-real/crs-engine.js`（675 行）
// 既是"保真度研究对象"，又充当 waf-real A/B 里"那个 WAF" —— 它自己判自己，绿得再稳也不构成
// 对外证据。而 modsec-live 的触发条件是 `if: schedule || workflow_dispatch`：
// push / PR 上**从不跑**，schedule 的 cron 又是 `0 3 * * 1`（每周一）
// ⇒ 真机校验每 7 天才有一次机会，且没人被要求看它。
//
// 本轮把 cron 改成**每日**（PR 时长不变，代价只落在 nightly）。本守卫防三种退化形态
// —— 与本仓 ciWindowsOnly.guard / ciWiring.guard 同构，三向缺一不可：
//   ① 检出：cron 必须含"每日"档 + modsec-live 的 if 必须仍含 schedule + 该 job 不得有
//      continue-on-error（run #10 曾靠它把失败显示成 success）+ 必须真的执行 modsec-live.mjs；
//   ② 不空转：解析器必须真命中 cron 与该 job（否则"零违规"可能是守卫自己的锅）；
//   ③ 反例自证：把四种退化各造一份合成 yml，判据必须红（不敏感 = 假绿）。
// ============================================================================

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '..', '..');
const CI_YML = path.join(REPO, '.github', 'workflows', 'ci.yml');
const ENGINE_SCRIPT = 'e2e/waf-real/modsec-live.mjs';

// [CRLF-FIX 2026-09-27] Windows 运行器 checkout 会把 LF 转成 CRLF（仓库 .gitattributes 只对
// 上游资产关了换行改写）。本守卫按行边界切 job（`:\n`），CRLF 下 `:\r\n` 匹配不到 →
// jobBlock 吞到文件尾、把别的 job 的 continue-on-error 误算进来（windows-latest 实测假红）。
// 统一按 LF 归一后再解析；配合 .gitattributes 对 workflows 的 -text 规则双保险。
const ci = readFileSync(CI_YML, 'utf8').replace(/\r\n/g, '\n');

/** 顶层 on.schedule 里的所有 cron 表达式 */
export function cronLines(text) {
  const m = text.match(/\n\s{2}schedule:\s*\n([\s\S]*?)(?=\n\s{2}\w|\njobs:)/);
  if (!m) return [];
  return [...m[1].matchAll(/cron:\s*['"]([^'"]+)['"]/g)].map((x) => x[1].trim());
}

/** jobs.<name> 的整段文本（到下一个同级 job 或文件尾） */
export function jobBlock(text, name) {
  const start = text.indexOf(`\n  ${name}:`);
  if (start < 0) return null;
  const rest = text.slice(start + 1);
  const next = rest.search(/\n {2}\w[\w-]*:\n/);
  return next < 0 ? rest : rest.slice(0, next);
}

/**
 * 返回违规清单。判据只做"结构性退化"检测，不猜具体业务数字。
 * @param {string} text ci.yml 全文
 */
export function auditNightlyEngine(text) {
  const bad = [];
  const crons = cronLines(text);
  if (!crons.length) {
    bad.push('顶层 on.schedule 里一条 cron 都没有 —— modsec-live 只能靠手动 dispatch 触发');
  } else {
    // 每日 = 分/时 + dom `*` + month `*` + dow `*`（dow 为 7 位数中第 5 个）
    const daily = crons.some((c) => /^\S+\s+\S+\s+\*\s+\*\s+\*\s*$/.test(c));
    if (!daily) bad.push(`schedule 不是每日档：${crons.join(' | ')} —— 真引擎对拍不能一周才跑一次`);
  }

  const block = jobBlock(text, 'modsec-live');
  if (!block) {
    bad.push('找不到 jobs.modsec-live —— 唯一的外部裁判被整段删除');
    return bad;
  }
  const ifLine = block.match(/^\s{4}if:\s*(.+)$/m);
  if (!ifLine || !/['"]schedule['"]/.test(ifLine[1])) {
    bad.push('modsec-live 的 job 级 if 不再包含 schedule ⇒ nightly 不会跑它');
  }
  if (/continue-on-error:\s*true/.test(block)) {
    bad.push('modsec-live 里出现 continue-on-error:true ⇒ 失败会被显示成 success（run #10 的形态）');
  }
  const runs = (block.match(new RegExp(ENGINE_SCRIPT.replace(/\./g, '\\.'), 'g')) || []).length;
  if (runs < 2) {
    bad.push(`modsec-live 对 ${ENGINE_SCRIPT} 的调用次数为 ${runs}（PL1 与切 PL3 重跑各 1 次）—— 少一次就少一档真机口径`);
  }
  return bad;
}

// ── ① 检出：当前配置必须已满足 ────────────────────────────────────────────────
test('真引擎对拍（modsec-live）每天有一次机会，且失败不会被吞', () => {
  assert.ok(existsSync(path.join(REPO, ENGINE_SCRIPT)), `取数源脚本 ${ENGINE_SCRIPT} 不存在`);
  const bad = auditNightlyEngine(ci);
  assert.deepEqual(bad, [], `ci.yml 的真机校验面退化：\n      ${bad.join('\n      ')}`);
});

// ── ② 不空转：解析器必须真的命中了东西 ────────────────────────────────────────
test('自证：解析器命中 cron 与 modsec-live（否则上面的"零违规"可能是守卫自己的锅）', () => {
  assert.ok(cronLines(ci).length >= 1, `cronLines 在真 ci.yml 上命中 0 条 —— 解析器失效（现有 ${cronLines(ci).length}）`);
  const block = jobBlock(ci, 'modsec-live');
  assert.ok(block && block.includes('modsec-live.mjs'), 'jobBlock 没解析到 modsec-live 的对拍步骤');
  // 边界切片自证：第一个 job 只该有它自己的内容，不许越到后面的 job 段里
  const lint = jobBlock(ci, 'lint');
  assert.ok(lint && lint.includes('runs-on'), 'jobBlock 连第一个 job 都没切出来 —— 边界正则失效');
  assert.ok(!lint.includes('modsec-live:'), 'jobBlock 切片越界（把后面的 job 也吞进来了）');
});

// ── ③ 反例自证：四种退化形态都必须红 ─────────────────────────────────────────
const weekly = ci.replace(/cron:\s*'[^']*'/, "cron: '0 3 * * 1'");
test('反例：cron 退回每周一 ⇒ 判据必须红', () => {
  assert.notDeepEqual(weekly, ci, '构造反例失败：真配置本来就不是每日？先查 ①');
  assert.ok(auditNightlyEngine(weekly).some((x) => /每日档/.test(x)), '周度 cron 没被判据抓住');
});

const noSchedule = ci.replace(/(modsec-live:\n\s+runs-on:[^\n]+\n)\s+if:[^\n]+/, '$1');
test('反例：modsec-live 的 if 去掉 schedule ⇒ 判据必须红', () => {
  assert.notEqual(noSchedule, ci, '构造反例失败：if 行没匹配到');
  assert.ok(auditNightlyEngine(noSchedule).some((x) => /job 级 if/.test(x)), '去掉 schedule 没被判据抓住');
});

const swallow = ci.replace(/(  modsec-live:\n)/, '$1    # continue-on-error 注入点\n');
const withContinueOn = ci.replace(/(  modsec-live:\n\s+runs-on:[^\n]+\n)/, '$1    continue-on-error: true\n');
test('反例：给 modsec-live 加 continue-on-error ⇒ 判据必须红', () => {
  assert.notEqual(withContinueOn, ci, '构造反例失败：runs-on 行没匹配到');
  assert.ok(auditNightlyEngine(withContinueOn).some((x) => /continue-on-error/.test(x)),
    'continue-on-error 没被判据抓住（它会把手动的"红"显示成 success）');
  void swallow;
});

const dropStep = ci.replace(/run: node e2e\/waf-real\/modsec-live\.mjs/g, 'run: echo "对拍被挪走了"');
test('反例：对拍步骤被换成 echo ⇒ 判据必须红', () => {
  assert.notEqual(dropStep, ci, '构造反例失败：没替换到任何对拍步骤');
  assert.ok(auditNightlyEngine(dropStep).some((x) => /调用次数/.test(x)), '步骤丢失没被判据抓住');
});
