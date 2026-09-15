// ============================================================================
// advise.js —— 扫描前风险评估（--advise）：只建议，不执行
//
// 设计原则（重要，勿改）：
//   · **不发任何请求**：评估只基于 URL 与参数，纯本地计算。
//   · **确定性**：同输入必同输出，可审计、可复现、零延迟、无外部依赖。
//     刻意**不调用 LLM**——LLM 有延迟/会幻觉/依赖 API，不能站在安全判断的临界路径上。
//     若将来要接 LLM，只能是「在下面这些确定性结论之外**补充**自然语言解释」。
//   · **不修改参数**：只打印建议；是否采纳由人决定（配 --yes 才继续扫描）。
//
// 一句话：LLM 负责解释，代码负责判断；本模块属于「代码负责判断」的那一半。
// ============================================================================

const LEVELS = ['低', '中', '高', '极高'];

// 保留给本地/内网/测试域的后缀：.local 是 mDNS 保留域，.test/.internal/.localhost 同理，
// 出现这些后缀基本可判定为非生产环境（首轮把它们误判成「公网域名」，评级会虚高）。
const NON_PROD_SUFFIX = /\.(local|test|internal|localhost|example|invalid)$/i;

function isPrivateOrLocal(host) {
  if (!host) return false;
  if (host === 'localhost' || host === '127.0.0.1' || host === '::1') return true;
  if (/^10\./.test(host)) return true;
  if (/^192\.168\./.test(host)) return true;
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(host)) return true;
  if (/^169\.254\./.test(host)) return true; // link-local（云元数据 169.254.169.254）
  if (NON_PROD_SUFFIX.test(host)) return true;
  return false;
}

function targetFacts(rawUrl) {
  const facts = [];
  let u = null;
  try {
    u = new URL(rawUrl);
  } catch {
    return [{ text: 'URL 无法解析', warn: true }];
  }
  const host = u.hostname;
  if (isPrivateOrLocal(host)) {
    facts.push({ text: `目标为内网/本机地址（${host}）`, warn: false, good: true });
  } else {
    facts.push({ text: `公网域名 ${host}`, warn: false });
  }
  if (u.protocol === 'http:') {
    facts.push({ text: '非 HTTPS：请求明文传输（可能被中间设备观测）', warn: true });
  } else {
    facts.push({ text: 'HTTPS', warn: false, good: true });
  }
  if (/(^|\.)(test|dev|staging|local|demo|lab)\./i.test(host) || /(^|-)(test|dev|stag)($|-)/i.test(host)) {
    facts.push({ text: '主机名含 test/dev/staging 特征（疑似非生产）', warn: false, good: true });
  } else if (!isPrivateOrLocal(host)) {
    facts.push({ text: '主机名未见非生产特征 —— 按生产目标对待', warn: false });
  }
  if (u.port && !['80', '443', ''].includes(u.port)) {
    facts.push({ text: `非标准端口 ${u.port}`, warn: false });
  }
  return facts;
}

/**
 * 构建风险评估。
 * @param {object} args parseArgs 的产物
 * @param {object} cfg buildConfig 的产物（含 concurrency/ratePerSec 等最终值）
 * @returns {{levelIndex:number, level:string, facts:Array, findings:Array, suggestions:string[]}}
 */
export function buildAdvice(args, cfg = {}) {
  const findings = [];
  const suggestions = [];
  let max = 0; // 0低 1中 2高 3极高
  const bump = (i) => { if (i > max) max = i; };

  const conc = Number(cfg.concurrency ?? args.concurrency);
  const rps = Number(cfg.ratePerSec ?? args.ratePerSec);
  const level = Number(args.level);
  const risk = Number(args.risk);
  const timeSec = Number(args.timeSec ?? cfg.timeBlindSleepSec);

  // ── 极高：可能造成不可逆后果 ─────────────────────────────────────────────
  if (args.osShell || args.fileWrite || args.sqlShell) {
    findings.push({
      sev: 3,
      text: '启用了写类利用（os-shell / file-write / sql-shell）：会修改目标系统状态，需明确授权且 EXPLOIT_ENABLED=1',
    });
    suggestions.push('确认已取得书面授权；先在克隆环境复现；为 --file-write 准备回滚方案');
    bump(3);
  }
  if (args.dumpAll) {
    findings.push({
      sev: 3,
      text: '--dump-all 会枚举所有库并逐库逐表拖数据：请求量巨大，且会读取目标全部数据',
    });
    suggestions.push('改用 -D/-T 限定库表；或加 --max-requests 设总量上限');
    bump(3);
  }

  // ── 高：破坏性或大范围 ───────────────────────────────────────────────────
  if (risk >= 3) {
    findings.push({
      sev: 2,
      text: '--risk=3 会启用破坏性 payload（DROP/UPDATE/写文件等），误用即造成数据损坏',
    });
    suggestions.push('非必要不超 --risk=2；确需 3 时先备份目标库');
    bump(2);
  }
  if (args.fileRead) {
    findings.push({ sev: 2, text: '--file-read 会读取目标主机文件（敏感信息外带）' });
    suggestions.push('限定具体路径；确认数据处置合规');
    bump(2);
  }
  if (args.commonTables) {
    findings.push({ sev: 2, text: '--common-tables 用字典逐个探针，请求量随字典线性增长' });
    suggestions.push('配合 --max-requests 限制总量');
    bump(2);
  }

  // ── 中：压力与面 ─────────────────────────────────────────────────────────
  if (level >= 3) {
    findings.push({ sev: 1, text: `--level=${level} 会显著增加 payload 变体与请求数` });
    suggestions.push('先用 --level=2 跑一轮，不够再加');
    bump(1);
  }
  if (conc >= 8) {
    findings.push({ sev: 1, text: `concurrency=${conc} 偏高，小型站点（PHP-FPM 进程数常为 5）可能被打满` });
    suggestions.push('降到 1-2（生产目标建议 1）');
    bump(1);
  }
  if (rps >= 50) {
    // 注意：args.ratePerSec 默认就是 50（CLI 面向本地靶场，见 args.js），
    // 与服务端 defaults.js 的 10 不一致 —— 所以这里要区分「默认值」与「用户显式配高」，
    // 否则每个用默认值的用户都会被判为「你配高了」，属于误报。
    const isDefault = Number(args.ratePerSec ?? 0) === 50 && rps === 50;
    findings.push({
      sev: 1,
      text: isDefault
        ? 'ratePerSec 默认 50（CLI 面向本地靶场的速度档），生产目标偏快'
        : `ratePerSec=${rps} 偏高，可能触发对方限流或耗尽连接池`,
    });
    suggestions.push(isDefault ? '生产目标加 --rate 5~10（服务端 API 默认即为 10）' : '降到 5-10');
    bump(1);
  }
  if (timeSec >= 5) {
    findings.push({ sev: 1, text: `time-sec=${timeSec}：时间盲注每次 sleep 都会占用数据库连接，易堆积` });
    suggestions.push('配合 --concurrency 1；或降到 2-3');
    bump(1);
  }
  if (args.testHeaders || args.testPath) {
    findings.push({ sev: 1, text: '--test-headers/--test-path 会额外测试头与 path 段，请求数增加' });
    suggestions.push('确认必要；注意这两个开关曾引入误报，需人工复核报告');
    bump(1);
  }
  if (Number(args.crawl) > 0) {
    findings.push({ sev: 1, text: `--crawl=${args.crawl} 会爬取链接扩大攻击面，可能触及未授权路径` });
    suggestions.push('配合 --scope 限定范围');
    bump(1);
  }

  // ── 缺失的防护（建议，不直接算风险）─────────────────────────────────────
  if (!args.safeUrl) {
    findings.push({ sev: 0, text: '未设置 --safe-url：目标被扫挂时无法自动发现（对标 sqlmap）' });
    suggestions.push('加 --safe-url <健康检查页> --safe-freq 20');
  }
  if (!args.scope) {
    findings.push({ sev: 0, text: '未设置 --scope：缺少「只能打授权资产」的硬边界' });
    suggestions.push('加 --scope 限定域名/IP 范围');
  }
  if (!args.maxRequests) {
    findings.push({ sev: 0, text: '未设置 --max-requests：请求总量无上限' });
    suggestions.push('加 --max-requests 设总量上限（如 5000）');
  }

  const facts = targetFacts(args.url || args.direct || '');
  return {
    levelIndex: max,
    level: LEVELS[max],
    facts,
    findings: findings.sort((a, b) => b.sev - a.sev),
    suggestions,
  };
}

const SEV_TEXT = ['提示', '中', '高', '极高'];
const SEV_MARK = ['·', '!', '!!', '!!!'];

/** 打印评估报告（不发起任何请求） */
export function printAdvice(advice, args) {
  const L = console.log;
  L('');
  L('============================================================================');
  L('  扫描前风险评估（--advise）—— 本评估未发起任何请求');
  L('============================================================================');
  L('');
  L(`  目标: ${args.url || args.direct || '(批量/直连)'}`);
  for (const f of advice.facts) {
    L(`    ${f.good ? '[ok]' : f.warn ? '[!]' : '[ ]'} ${f.text}`);
  }
  L('');
  L(`  风险等级: ${advice.level}`);
  L('');

  if (!advice.findings.length) {
    L('  未发现明显风险项：参数在保守区间，且关键防护已就位。');
  } else {
    L('  发现的问题:');
    for (const f of advice.findings) {
      L(`    ${SEV_MARK[f.sev]} [${SEV_TEXT[f.sev]}] ${f.text}`);
    }
  }

  if (advice.suggestions.length) {
    L('');
    L('  建议:');
    for (const s of advice.suggestions) {
      L(`    - ${s}`);
    }
  }

  L('');
  L('  保守参数参考（生产目标）:');
  L('    --concurrency 1 --ratePerSec 5 --delay 200 --max-requests 5000');
  L('    --safe-url <健康检查页> --safe-freq 20 --scope <授权范围>');
  L('');
  L('  说明: 本评估为确定性规则（不调用 LLM），只给建议、不修改你的参数。');
  L('        采纳与否由你决定；加 --yes 可在打印后继续扫描。');
  if (advice.levelIndex >= 3) {
    L('');
    L('  ⚠ 风险等级为「极高」：--yes 不足以继续。');
    L('    请确认已取得书面授权、已备份目标库、并确认以下开关，然后重跑：');
    L('');
    L('      --advise --yes --confirm-extreme');
    L('');
    L('    （把「看过建议」与「接受后果」分成两个动作，避免手快回车。）');
  }
  L('');
}

/**
 * 极高危（levelIndex>=3）时是否允许继续。
 * 设计意图：`--yes` 只代表「我看过建议了」，极高危还要求 `--confirm-extreme`
 * 代表「我接受可能的不可逆后果」——把两个动作分开，避免一次回车扫平生产库。
 * @param {object} advice buildAdvice 的产物
 * @param {object} args parseArgs 产物
 * @returns {boolean}
 */
export function allowedToContinue(advice, args) {
  if (advice.levelIndex < 3) return Boolean(args.yes);
  return Boolean(args.yes && args.confirmExtreme);
}

export default buildAdvice;
