// ============================================================================
// modsec-live.mjs —— 真机 ModSecurity（owasp/modsecurity-crs:nginx）对拍
//
// 与 tamper-sweep.mjs 的关系：
//   tamper-sweep = **静态**（自实现 crs-engine 执行官方规则原文，不发包）
//   本脚本      = **真机**（真实 ModSecurity + libinjection 引擎，真发 HTTP）
// 两者共用 samples.mjs 的同一批样本 → 差异只可能来自「引擎不同」，不会来自「样本不同」。
//
// ── 2026-09-28 升级：从「放行率」到「打穿率」────────────────────────────────
// 首轮（09-27）只能证明「WAF 放行了」，因为靶站是 echo 后端、不执行 SQL。
// 仓库当时把这条写进诚实边界并**禁止对外声明绕过率**。本版补的就是那一环：
// 同一条样本要同时满足 ① 过了 WAF ② 后端真 MySQL 真执行了注入并吐出证据，
// 才记为一次「打穿」。两个通道都量：
//   · WAF 通道（经 ModSecurity 反代）→ 放行 / 打穿
//   · 直连通道（绕过 WAF 直接打靶站）→ **可打穿上界**。打穿率的分母来自它，
//     这样才能把「变形把 payload 语义弄坏了」与「WAF 真拦住了」分开。
//
// ⚠️ 判据分层（判据必须与危害同源）：
//   L1 抵达 SQL 层 = body 以 `ROWS:`/`SQLERR:` 开头（说明请求真的拼进 SQL 跑过）
//   L2 取数成功   = ① 结果集里出现注入标记，或 ② MySQL 报错里出现注入函数专属短语
//   只认这两类 MySQL **自己生成**的文本；**绝不**用「body 里出现 payload」当证据 ——
//   echo 后端的回显会让任何回显型判据恒真（本仓反复踩的「巧合陷阱」）。
//
// ⚠️ 红的条件只有一条：**自检不通过**（后端没起来 / WAF 没生效 / 靶站不可注入 / 要求真库却没有库）。
//   这类失败意味着「下面所有数字都不是在测 WAF」—— 判据与危害同源，必须硬失败。
//   其余（放行多少、打穿多少、误报几条）都是**测量值**，不是本仓的成败判据：
//   · 打穿少 → 是 CRS 强，不是我们做错了；
//   · 误报多 → 是 CRS 的问题（要记录、要归因），不该让我们的 CI 变红。
//   （本仓反复踩的坑就是「恒绿的空转门禁」；反过来「把别人的问题算成自己的红」同样失真。）
//
// 用法：
//   node e2e/waf-real/modsec-live.mjs
//   MODSEC_BASE=http://127.0.0.1:8080 MODSEC_LABEL=pl1 node e2e/waf-real/modsec-live.mjs
//   MODSEC_REQUIRE_DB=1 node e2e/waf-real/modsec-live.mjs    # 要求真库靶站，降级即失败
// ============================================================================
import { spawn } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import { SAMPLES, SAFE_SAMPLES, CONTEXTS, payloadOf, sampleUrl } from './samples.mjs';
import { evaluate } from './crs-engine.js';
import { verdict, isPwn, atSql } from './pwnVerdict.mjs';

const require = createRequire(new URL('../../server/package.json', import.meta.url));
const here = dirname(fileURLToPath(import.meta.url));
const { applyTampers } = require(resolve(here, '../../server/src/core/tamper/applyTampers.js'));
const { tamperRegistry } = require(resolve(here, '../../server/src/core/tamper/TamperRegistry.js'));

const BASE = process.env.MODSEC_BASE || 'http://127.0.0.1:8080';
const LABEL = process.env.MODSEC_LABEL || 'pl1';
const TARGET_PORT = Number(process.env.MODSEC_TARGET_PORT || 8151);
const DIRECT = process.env.MODSEC_DIRECT_BASE || `http://127.0.0.1:${TARGET_PORT}`;
const REQUIRE_DB = process.env.MODSEC_REQUIRE_DB === '1';
/**
 * 直连打穿上界的**下限**（默认 1：只要还测得动就出数）。
 * 这是**本仓自己的**质量闸门，不是 WAF 的成败：直连通道绕过了 WAF，上界只取决于
 * 「样本 × 靶站拼接形态」，低了就是我们的样本集/靶站没配好 → 打穿率不可引用。
 */
const MIN_UPPER = Number(process.env.MODSEC_MIN_UPPER || 1);
const PER_CHAIN_DIRECT = process.env.MODSEC_DIRECT_PER_CHAIN !== '0';
const OUT_DIR = resolve(here, 'results');
const DATE = new Date().toISOString().slice(0, 10);

const ctx = { dbms: 'MySQL', config: {} };

// ── 靶站（真库模式见 modsec-target.mjs；容器内 nginx 反代到它）────────────────
// 若外部（CI workflow / 手工）已经拉起则复用；没人应答才自己 spawn 一个兜底。
// 这**不改变**「CI 里由 workflow 先起靶站」的次序约定（容器启动时上游必须在位）。
async function probeMode() {
  try {
    const r = await fetch(`${DIRECT}/__mode`, { signal: AbortSignal.timeout(2000) });
    if (!r.ok) return { mode: 'unknown', reason: `HTTP ${r.status} 于 /__mode` };
    return await r.json();
  } catch {
    return null;
  }
}

async function ensureTarget() {
  const seen = await probeMode();
  if (seen) return { mode: seen.mode, reason: seen.reason || null, child: null, logs: [] };

  const child = spawn(process.execPath, [resolve(here, 'modsec-target.mjs')], {
    env: process.env,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const logs = [];
  child.stdout.on('data', (d) => logs.push(String(d).trim()));
  child.stderr.on('data', (d) => logs.push(String(d).trim()));
  const t0 = Date.now();
  while (Date.now() - t0 < 10000) {
    const m = await probeMode();
    if (m) return { mode: m.mode, reason: m.reason || null, child, logs };
    await new Promise((r) => setTimeout(r, 200));
  }
  return { mode: 'down', reason: '自起靶站 10s 内未就绪', child, logs };
}

/** 打一发，返回 { status, text }；网络异常返回 { status: 0 }
 *  ⚠️ 走 sampleUrl（samples.mjs 单一来源）：样本自带 ctx → path/param 由它决定，
 *     这里再手拼一遍 URL 就会出现「样本说 str、请求打 num」的错配（上界归零的根因）。 */
async function hit(base, payload) {
  const url = sampleUrl(base, payload);
  try {
    const r = await fetch(url, { redirect: 'manual' });
    return { status: r.status, text: (await r.text()).slice(0, 400) };
  } catch (e) {
    return { status: 0, text: `ERR:${e.message}` };
  }
}

/** WAF 判定：非 2xx = 被拦；网络不通（0）= 不可判定（由调用方按错误处理） */
const blocked = (r) => r.status >= 400;

// ── 打穿判据（verdict / isPwn / atSql）已抽到 `pwnVerdict.mjs` ───────────────
// 抽出的理由：这段逻辑决定「算不算打穿」，是本轮所有数字的根；留在本文件里
// 无法被单测覆盖（导入会触发 main 的副作用），只能靠「读起来对」。
// 判据本身的两条防假绿纪律写在那个模块里，守卫见
// `server/tests/modsecLive.wiring.test.js`（含「echo 回显 payload ≠ 打穿」反例）。

/** 对一批样本跑一个通道，返回逐条 verdict */
async function sweep(base, chain) {
  const vs = [];
  for (const s of SAMPLES) {
    let t = payloadOf(s);
    try {
      t = chain ? applyTampers(payloadOf(s), ctx, chain) : payloadOf(s);
    } catch { /* 插件抛错 → 按原样发（与 tamper-sweep 同口径：错误单独记） */ }
    // ctx 跟着样本走：变形只改 payload，不改它该打哪个端点
    vs.push(verdict(await hit(base, { ...s, payload: t })));
  }
  return vs;
}

/** 静态侧（自实现 crs-engine）对同一批样本、同一条链的判定 → 分歧归因用 */
function staticSweep(chain) {
  let pass = 0;
  const rules = [];
  for (const s of SAMPLES) {
    const c = CONTEXTS[s.ctx];
    let t = payloadOf(s);
    try {
      t = chain ? applyTampers(payloadOf(s), ctx, chain) : payloadOf(s);
    } catch { /* 同上 */ }
    const e = evaluate({
      uri: `${c.path}?${c.param}=1`,
      queryString: `${c.param}=${encodeURIComponent(t)}`,
      args: { [c.param]: t },
      cookies: {},
      headers: {},
    });
    if (!e.blocked) pass++;
    else rules.push(e.ruleId || '?');
  }
  return { pass, rules: [...new Set(rules)] };
}

// ── 自检：三条都必须成立，否则 exit 1 ───────────────────────────────────────
// （WAF 在位 / 后端可达 / 靶站本身可注入 —— 少任何一条，下面的数字都不成立）
async function selftest() {
  // 干净请求用 num 形态（`WHERE id = 1`）；裸注入用 str 形态（`WHERE name = '1' AND 1=1-- -'`）——
  // 后者在数值上下文里是语法错误，拿它验证「WAF 在不在位」会掺进一个与 WAF 无关的干扰项。
  const clean = await hit(BASE, { ctx: 'num', payload: '1' });
  if (clean.status === 0) {
    console.error(`[自检失败] 连不上 ${BASE} —— 容器没起来或端口不对（${clean.text}）`);
    return null;
  }
  if (!String(clean.status).startsWith('2')) {
    console.error(`[自检失败] 干净请求 id=1 被拦（HTTP ${clean.status}）—— 被拦的是正常流量，说明 WAF 阈值/规则集不是我们要测的形态`);
    return null;
  }
  const probe = await hit(BASE, { ctx: 'str', payload: "1' AND 1=1-- -" });
  if (!blocked(probe)) {
    console.error(
      `[自检失败] 裸注入 name=1' AND 1=1-- - 未被拦（HTTP ${probe.status}）—— WAF 没在阻断` +
        `（常见成因：镜像默认 SecRuleEngine=DetectionOnly / 反代没走 ModSecurity / PARANOIA 环境变量名随版本变）。` +
        `不修这个就跑数字，等于在测一个不存在的 WAF。`
    );
    return null;
  }
  // 第三条：靶站**本身可不可注入**。没有它，「经 WAF 打穿 0 条」可能是靶站坏了而不是 WAF 强。
  const directVerdicts = await sweep(DIRECT, null);
  const upper = directVerdicts.filter(isPwn).length;
  if (directVerdicts.some((v) => v === 'echo')) {
    if (REQUIRE_DB) {
      console.error(
        `[自检失败] MODSEC_REQUIRE_DB=1 但靶站不是真库模式（直连响应无 SQL 层证据）—— ` +
          `本轮只能得「放行率」、拿不到「打穿率」。降级必须是**可见的失败**，不能静默出数。`
      );
      return null;
    }
    console.warn('[自检降级] 靶站处于 echo 模式 → 本轮只出「放行率」，报告会如实标注（打穿列记不可判定）');
    return { clean, probe, upper: null, directVerdicts };
  }
  if (upper === 0) {
    console.error(
      `[自检失败] 直连靶站（绕过 WAF）${SAMPLES.length} 条样本**一条都没打穿** —— 靶站或判据坏了，` +
        `此时「经 WAF 打穿 0 条」不能归因于 WAF。逐条 verdict：${directVerdicts.join(', ')}`
    );
    return null;
  }
  // 上界过低 = 样本与靶站形态不匹配（2026-09-28 实测 1/8 就是这个病灶）→ 打穿率的分母太小，
  // 任何百分比都建立在个别样本上。默认只告警（1 条以上就算测得了），CI 可用 MIN_UPPER 收紧。
  if (upper < MIN_UPPER) {
    console.error(
      `[自检失败] 直连打穿上界 ${upper}/${SAMPLES.length}，低于要求 ${MIN_UPPER} —— ` +
        `样本集分辨率不够（多半是样本与该上下文的拼接形态不匹配），此时打穿率不可引用。` +
        `逐条 verdict：${directVerdicts.join(', ')}`
    );
    return null;
  }
  if (upper * 2 < SAMPLES.length) {
    console.warn(
      `[上界偏低] 直连只打穿 ${upper}/${SAMPLES.length} —— 打穿率的分母偏小，` +
        `引用前先看报告「直连上界」那一列（哪几条样本本身取不到数）`
    );
  }
  return { clean, probe, upper, directVerdicts };
}

async function main() {
  const target = await ensureTarget();
  for (const l of target.logs || []) console.log(`[靶站] ${l}`);
  if (target.mode === 'down') {
    console.error(`[自检失败] 靶站不可用：${target.reason}`);
    target.child?.kill('SIGTERM');
    process.exit(1);
  }

  const st = await selftest();
  if (!st) {
    target.child?.kill('SIGTERM');
    process.exit(1);
  }
  console.log(`[自检通过] 干净请求 HTTP ${st.clean.status} · 裸注入 HTTP ${st.probe.status}（已拦）· BASE=${BASE} · LABEL=${LABEL}`);
  console.log(
    `[靶站] 模式=${target.mode}${target.reason ? `（${target.reason}）` : ''} · 直连打穿上界 ` +
      `${st.upper === null ? '不可判定（echo 模式）' : `${st.upper}/${SAMPLES.length}`}`
  );

  const names = tamperRegistry.list().map((p) => (typeof p === 'string' ? p : p.name)).sort();
  const rows = [];

  const run = async (label, chain) => {
    const wafV = await sweep(BASE, chain); // 经 WAF
    const directV = PER_CHAIN_DIRECT || chain === null ? await sweep(DIRECT, chain) : null; // 绕过 WAF
    rows.push({
      label,
      wafPass: wafV.filter((v) => v !== 'blocked' && v !== 'unknown').length,
      wafPwn: wafV.filter(isPwn).length,
      wafSql: wafV.filter(atSql).length,
      unknown: wafV.filter((v) => v === 'unknown').length,
      directPwn: directV ? directV.filter(isPwn).length : null,
      static: staticSweep(chain),
    });
  };

  await run('(off) 不做变形', null);
  for (const n of names) await run(n, [n]);

  // 安全对照：期望 0 误拦；有就记录（是 CRS 的误报，不是我们的回归 → 不红）
  const fp = [];
  for (const s of SAFE_SAMPLES) {
    const r = await hit(BASE, s);
    if (blocked(r)) fp.push({ sample: `${s.ctx}:${payloadOf(s)}`, status: r.status });
  }
  target.child?.kill('SIGTERM');

  rows.sort((a, b) => b.wafPwn - a.wafPwn || b.wafPass - a.wafPass || a.label.localeCompare(b.label));
  const winners = rows.filter((r) => r.wafPwn > 0 && r.label !== '(off) 不做变形');
  const dbMode = st.upper !== null;

  console.log(`\n插件 ${names.length} 个 · 样本 ${SAMPLES.length} 条 · LABEL=${LABEL} · 靶站模式=${target.mode}`);
  console.log('打穿(真机) | 放行(真机) | 直连上界 | 放行(自实现) | 链');
  for (const r of rows.slice(0, 25)) {
    const flag = r.wafPwn > 0 ? '  ★' : '   ';
    console.log(
      `${flag} ${String(r.wafPwn).padStart(2)}/${SAMPLES.length}        ` +
        `${String(r.wafPass).padStart(2)}/${SAMPLES.length}        ` +
        `${r.directPwn === null ? '  —  ' : `${String(r.directPwn).padStart(2)}/${SAMPLES.length}`}        ` +
        `${String(r.static.pass).padStart(2)}/${SAMPLES.length}        ${r.label}`
    );
  }

  // ── 报告 ────────────────────────────────────────────────────────────────
  const md = [];
  md.push(`# 真机 ModSecurity 对拍（${LABEL}）· ${DATE}`, '');
  md.push('## 四要素 + 靶站形态（结果可比性的前提，缺一不可）', '');
  md.push('| 项 | 值 |');
  md.push('|---|---|');
  md.push(`| 镜像 | \`${process.env.MODSEC_IMAGE || 'owasp/modsecurity-crs:nginx（tag 未记录）'}\` |`);
  md.push(`| 镜像 digest | \`${process.env.MODSEC_DIGEST || '未记录'}\` |`);
  md.push(`| CRS 版本 | ${process.env.MODSEC_CRS_VERSION || '未记录（容器内 /etc/modsecurity.d 取证失败）'} |`);
  md.push(`| PARANOIA | ${process.env.MODSEC_PARANOIA || '未记录'} |`);
  md.push(`| 阻断阈值 | ${process.env.MODSEC_ANOMALY_INBOUND || '未记录'} |`);
  md.push(`| 靶站 | \`modsec-target.mjs\` @${DIRECT} · **模式 ${target.mode}**${target.reason ? `（${target.reason}）` : ''} |`);
  md.push('', `自检：干净请求 HTTP ${st.clean.status}（放行）· 裸注入 HTTP ${st.probe.status}（已拦）· 直连打穿上界 ${st.upper === null ? '不可判定' : `${st.upper}/${SAMPLES.length}`}`, '');

  if (!dbMode) {
    md.push(
      '> ⚠️ **本轮是降级运行（靶站 echo，无真库）**：只能给出「放行」数字，',
      '> 「打穿」列一律记 `不可判定`。**不得**把放行数当成绕过能力对外引用。',
      ''
    );
  }

  md.push('## 注入点形态（靶站拼接模板；样本按 ctx 打各自的端点）', '');
  for (const [k, c] of Object.entries(CONTEXTS)) {
    md.push(`- \`${k}\` → \`${c.path}?${c.param}=…\` · \`${c.sql('${raw}')}\``);
  }
  md.push('');

  md.push('## 直连上界（绕过 WAF 直接打靶站：每条样本本身能打穿到什么程度）', '');
  md.push('| # | 上下文 | 样本 | 直连判定 |');
  md.push('|---|---|---|---|');
  st.directVerdicts.forEach((v, i) => {
    md.push(`| ${i + 1} | \`${SAMPLES[i].ctx}\` | \`${payloadOf(SAMPLES[i]).slice(0, 70)}\` | ${v} |`);
  });
  md.push(
    '',
    `> 口径：上界 = 本批样本不经 WAF 时真正取到数据的条数（${st.upper === null ? '不可判定' : `${st.upper}/${SAMPLES.length}`}）。`,
    '> 「变形后语义被破坏」与「WAF 真拦住了」靠这一列分开 —— 打穿率的分母是它，不是样本总数。',
    ''
  );

  md.push('## 对拍矩阵（真机 vs 自实现 crs-engine）', '');
  md.push('| 链 | 打穿(真机) | 放行(真机) | 直连上界 | 放行(自实现) | 自实现命中规则 |');
  md.push('|---|---|---|---|---|---|');
  for (const r of rows) {
    if (r.wafPass === 0 && r.static.pass === 0 && r.wafPwn === 0) continue;
    md.push(
      `| \`${r.label}\` | ${dbMode ? `${r.wafPwn}/${SAMPLES.length}` : '不可判定'} | ${r.wafPass}/${SAMPLES.length} | ` +
        `${r.directPwn === null ? '—' : `${r.directPwn}/${SAMPLES.length}`} | ${r.static.pass}/${SAMPLES.length} | ${r.static.rules.join(', ') || '—'} |`
    );
  }
  md.push('');
  md.push(`真机**打穿**的插件（${winners.length}）：${winners.length ? winners.map((r) => `\`${r.label}\``).join(', ') : '（无）'}`, '');
  const anyPass = rows.filter((r) => r.wafPass > 0 && r.label !== '(off) 不做变形');
  md.push(`真机**放行**（未拦）的插件（${anyPass.length}）：${anyPass.length ? anyPass.map((r) => `\`${r.label}\``).join(', ') : '（无）'}`, '');

  md.push('## 安全对照（期望 0 误拦）', '');
  md.push(fp.length ? fp.map((x) => `- \`${x.sample}\` → HTTP ${x.status}（CRS 误报，非本工具回归）`).join('\n') : '- 0 误拦 ✅');
  md.push('');
  md.push('## 口径（引用这几个数字前必须读）', '');
  md.push('1. **打穿 ≠ 绕过率**。分母是 `samples.mjs` 的固定样本数；逐样本的可用上界见上一节，', '   两者相除才是该链的绕过成功率。');
  md.push('2. **放行 ≠ 打穿**。放行只说明请求到了后端，不代表 SQL 执行、更不代表取到数据。');
  md.push('3. 判定只采信 MySQL 自己生成的证据（结果集标记 / MySQL 报错短语），', '   不使用「响应里出现 payload」这类回显型判据 —— echo 后端下它会恒真。');
  md.push('4. 本轮为**测量**，不是通过/失败判据；唯一让本脚本退出 1 的是「自检不通过」', '   （WAF 不在位 / 靶站不可注入 / 要求真库却没有真库）。');
  mkdirSync(OUT_DIR, { recursive: true });
  const out = resolve(OUT_DIR, `modsec-docker-${LABEL}-${DATE}.md`);
  writeFileSync(out, md.join('\n'), 'utf8');
  console.log(`\n报告：${out}`);
  if (fp.length) console.warn(`[注意] 安全对照误拦 ${fp.length} 条（CRS 侧误报，已写入报告，不计失败）`);
  process.exit(0);
}

main().catch((e) => {
  console.error(`[modsec-live] 未预期异常：${e && e.stack ? e.stack : e}`);
  process.exit(1);
});
