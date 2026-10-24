// ============================================================================
// scripts/lib/workflowLint.mjs —— [D149 2026-10-24] GitHub Actions 工作流的结构判据（纯函数）
//
// 为什么需要：仓库现在有 4 个 workflow（ci / codeql / …），而它们的**结构错误**只有
// GitHub 才知道（push 上去才红，本地无从验证）。本机不能跑 Actions，但**结构**是可静态判的：
//   · 丢 `runs-on`（job 直接不合法）        · `needs:` 指向不存在的 job（依赖图断）
//   · 空步骤 / 步骤既无 `uses` 也无 `run`  · 第三方 action 未钉版本（供应链风险 + 漂移）
//   · 同一文件里 job 重名（YAML 重复键）
// 这些正是「本地全绿、CI 红」最省事的一类，且判据可以完全离线跑。
//
// 口径：只判**结构**，不判业务语义（哪个 job 该跑什么由各自的门禁守）。
// 解析由调用方负责（测试里用 devDependency `yaml`），本模块只吃已解析的对象，
// 这样判据本身可以被合成样本直接检验（见 server/tests/ciWorkflows.guard.test.js）。
// ============================================================================

/** 合法 job 名（GitHub：字母数字、`-`、`_`，不能以 `-`/`_` 开头） */
const JOB_NAME_RE = /^[A-Za-z_][A-Za-z0-9_-]*$/;
/** 合法 action 引用：`owner/repo@v4` / `@v4.1.2` / `@<40 位 sha>` / 本地 `./path` / `docker://` */
const PINNED_RE = /@(v?\d+(\.\d+){0,2}|[0-9a-f]{40})$/i;

/**
 * **条件性豁免**：允许不钉版本号，但必须给出真正钉住行为的东西。
 * 本仓只有一处：`dtolnay/rust-toolchain@master`（CI 注释已论证：`@stable` 每次拉最新 stable；
 * 版本由 `with.toolchain` + `src-tauri/rust-toolchain.toml` 钉死）。豁免是**带条件的**：
 * 缺了 `with.toolchain` 就报错 —— 否则总有一天有人只留 `@master`，而版本悄悄漂走。
 * @type {Record<string, { requiresWith: string, why: string }>}
 */
const CONDITIONAL_UNPINNED = {
  'dtolnay/rust-toolchain@master': {
    requiresWith: 'toolchain',
    why: '版本由 with.toolchain + src-tauri/rust-toolchain.toml 钉死（见 CI 注释）',
  },
};

/** 每个 job 至少要能跑起来：`uses`（可复用工作流）或 `steps`（普通 job）+ `runs-on` */
function lintJobShape(doc, file, problems) {
  for (const [name, job] of Object.entries(doc.jobs ?? {})) {
    const where = `${file}: jobs.${name}`;
    if (!JOB_NAME_RE.test(name)) problems.push(`${where} —— job 名不合法（GitHub 规则：字母数字/-/_，不以 -/_ 开头）`);
    if (!job || typeof job !== 'object') {
      problems.push(`${where} —— job 体不是对象`);
      continue;
    }
    const reusable = typeof job.uses === 'string';
    if (!reusable && !job['runs-on']) problems.push(`${where} —— 缺 runs-on（job 会被 GitHub 直接拒）`);
    if (reusable && job['runs-on']) problems.push(`${where} —— 可复用工作流 job 不该写 runs-on（写了也无效，容易被误读）`);
    if (reusable) continue;
    if (!Array.isArray(job.steps) || job.steps.length === 0) problems.push(`${where} —— steps 为空（这个 job 什么也不做）`);
  }
}

/**
 * 每个 job 必须显式写 `timeout-minutes`（D150）。
 * 为什么：不写时 GitHub 的默认上限是 **360 分钟**——挂住的 job 会烧满 6 小时 runner 配额，
 * 而挂住最常见的原因恰恰是本仓已有过的形态（等服务端口、等回连、死锁）。
 * 显式值既是成本闸，也是「这个 job 正常多久」的口径声明。
 * @param {any} doc 已解析的 workflow
 * @param {string} file 文件名
 * @param {string[]} problems 累积问题
 * @returns {void}
 */
function lintTimeouts(doc, file, problems) {
  for (const [name, job] of Object.entries(doc.jobs ?? {})) {
    if (typeof job?.uses === 'string') continue; // 可复用工作流的超时由被调用方声明
    const raw = job?.['timeout-minutes'];
    if (raw == null) {
      problems.push(`${file}: jobs.${name} —— 缺 timeout-minutes（不写则默认上限 360 分钟，挂住的 job 会烧满配额）`);
      continue;
    }
    const n = Number(raw);
    if (!Number.isFinite(n) || n <= 0 || n > 360) {
      problems.push(`${file}: jobs.${name}.timeout-minutes —— 非法值：${String(raw)}（应为 1..360 的分钟数）`);
    }
  }
}

/** `needs:` 指向的 job 必须存在（依赖图断掉时 GitHub 报的是整份 workflow 无效） */
function lintNeeds(doc, file, problems) {
  const names = new Set(Object.keys(doc.jobs ?? {}));
  for (const [name, job] of Object.entries(doc.jobs ?? {})) {
    const needs = Array.isArray(job?.needs) ? job.needs : job?.needs ? [job.needs] : [];
    for (const dep of needs) {
      if (typeof dep !== 'string') problems.push(`${file}: jobs.${name}.needs —— 依赖项必须是字符串`);
      else if (!names.has(dep)) problems.push(`${file}: jobs.${name}.needs —— 依赖的 job「${dep}」不存在（依赖图断）`);
    }
  }
}

/** 每个 step 必须二选一：`uses` 或 `run`（两个都没有 = 空步骤，GitHub 拒收） */
function lintSteps(doc, file, problems) {
  for (const [name, job] of Object.entries(doc.jobs ?? {})) {
    for (const [i, step] of (job?.steps ?? []).entries()) {
      const where = `${file}: jobs.${name}.steps[${i}]`;
      if (!step || typeof step !== 'object') {
        problems.push(`${where} —— step 不是对象`);
        continue;
      }
      const hasUses = typeof step.uses === 'string';
      const hasRun = typeof step.run === 'string';
      if (!hasUses && !hasRun) problems.push(`${where} —— 既无 uses 也无 run（空步骤）`);
      if (hasUses && hasRun) problems.push(`${where} —— uses 与 run 同时存在（run 会被忽略，属误写）`);
      if (hasRun && !step.run.trim()) problems.push(`${where} —— run 为空字符串`);
    }
  }
}

/** 硬编码凭据形态（workflow 是明文入库的，任何 token 写进去等于公开） */
const SECRET_PATTERNS = [
  [/ghp_[A-Za-z0-9]{20,}/, 'GitHub PAT（ghp_…）'],
  [/github_pat_[A-Za-z0-9_]{20,}/, 'GitHub fine-grained PAT（github_pat_…）'],
  [/AKIA[0-9A-Z]{16}/, 'AWS Access Key ID（AKIA…）'],
  [/sk-[A-Za-z0-9]{20,}/, 'OpenAI 风格密钥（sk-…）'],
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----/, '私钥块'],
];

/**
 * workflow 里不得出现硬编码凭据（D150）：`${{ secrets.X }}` 才是唯一正确写法。
 * 只扫明文，`${{ secrets.… }}` 与 `${{ github.token }}` 表达式不算。
 * 不导出：只有 lintWorkflowDoc 用它（deadcode 门禁把「无人 import 的导出」算死代码）；
 * 测试通过带 `text` 的 lintWorkflowDoc 覆盖它。
 * @param {string} text workflow 原文
 * @param {string} file 文件名
 * @returns {string[]} 问题列表
 */
function lintNoHardcodedSecrets(text, file) {
  const problems = [];
  const lines = String(text ?? '').split(/\r?\n/);
  for (const [i, line] of lines.entries()) {
    const code = line.replace(/\$\{\{[^}]*\}\}/g, ' EXPR '); // 表达式占位，避免把 secrets 引用本身当凭据
    for (const [re, label] of SECRET_PATTERNS) {
      if (re.test(code)) problems.push(`${file}:${i + 1} —— 疑似硬编码${label}（应改用 \${{ secrets.X }}）`);
    }
  }
  return problems;
}

/**
 * 第三方 action 必须钉版本（`@v4` / `@v4.1.2` / `@<sha>`）。
 * 本仓口径：不钉版本 = 供应链风险 + 行为随上游漂移（本仓已因版本漂移吃过 D77 的亏）。
 * @param {any} doc 已解析的 workflow 对象
 * @param {string} file 文件名（用于报错定位）
 * @param {string[]} problems 累积问题
 * @returns {void}
 */
function lintUsesPinned(doc, file, problems) {
  for (const [name, job] of Object.entries(doc.jobs ?? {})) {
    for (const [i, step] of (job?.steps ?? []).entries()) {
      const uses = step?.uses;
      if (typeof uses !== 'string') continue;
      if (uses.startsWith('./') || uses.startsWith('docker://')) continue; // 本地 action / 容器动作不走版本钉
      if (PINNED_RE.test(uses)) continue;
      const waiver = CONDITIONAL_UNPINNED[uses];
      if (waiver) {
        // 条件性豁免：真正钉住行为的东西必须在场（缺了就报 —— 豁免不许退化成「随便不钉」）
        if (!step?.with || step.with[waiver.requiresWith] == null) {
          problems.push(
            `${file}: jobs.${name}.steps[${i}].uses —— ${uses} 属条件性豁免（${waiver.why}），` +
              `但缺 with.${waiver.requiresWith} ⇒ 版本实际没被钉住`
          );
        }
        continue;
      }
      problems.push(`${file}: jobs.${name}.steps[${i}].uses —— 未钉版本：${uses}（应写 @vN / @vN.N.N / @<sha>）`);
    }
  }
}

/**
 * 工作流结构体检（纯函数，输入是已解析的对象）。只判结构，不判业务语义。
 * @param {{ doc: any, file: string, emptyOk?: boolean }} input 已解析的 workflow 与其文件名
 * @returns {string[]} 问题列表（空数组 = 通过）
 */
export function lintWorkflowDoc({ doc, file, emptyOk = false, text = null }) {
  const problems = [];
  if (text != null) problems.push(...lintNoHardcodedSecrets(text, file));
  if (!doc || typeof doc !== 'object') return [`${file} —— 顶层不是对象（YAML 解析失败或内容为空）`];
  if (!doc.jobs || typeof doc.jobs !== 'object' || Object.keys(doc.jobs).length === 0) {
    // 只有显式声明「允许没有 job」时才算过（例如占位文件）；默认视为错误，避免空 workflow 静默通过
    return problems.concat(emptyOk ? [] : [`${file} —— 没有 jobs（workflow 什么也不做）`]);
  }
  lintJobShape(doc, file, problems);
  lintTimeouts(doc, file, problems);
  lintNeeds(doc, file, problems);
  lintSteps(doc, file, problems);
  lintUsesPinned(doc, file, problems);
  return problems;
}