// ============================================================================
// gate-list.mjs —— 收口清单的**单一真源**（D178 从 gate-close.mjs 抽出）
//
// 为什么要抽出来：清单原本只活在 `scripts/gate-close.mjs` 里，谁想「读一下现在有
// 多少项门禁」都得复制一份 → 复制品必然漂移。质量台账（scripts/quality-ledger.mjs）
// 要展示项数，于是把它抽成模块：**一份清单，两个消费者**（执行 + 展示）。
// ============================================================================
import { readdirSync } from 'node:fs';
import { join } from 'node:path';

/**
 * wiring 测试文件（门禁与接线测试；防虚高等判据只在测试里，不在门禁输出里）。
 * [2026-10-18 修正] 原匹配 `f.includes('Guard')` 大小写敏感，把 26 个 `*.guard.test.js`
 * （含 D89 wafExternalParity.guard / wafSamples.guard 等）漏在收口清单之外——它们只在
 * `cd server && npm test` 的全量里被兜底跑，gate:close 看不见。改成大小写不敏感，
 * 使“守卫类测试”与“wiring 类测试”全部被收口。
 * @param {string} root 仓库根
 * @returns {string[]} 相对仓库根的测试文件路径（按名字排序）
 */
export function wiringTestFiles(root) {
  const dir = join(root, 'server', 'tests');
  return readdirSync(dir)
    .filter((f) => {
      const lower = f.toLowerCase();
      return lower.endsWith('.test.js') && (lower.includes('guard') || lower.includes('wiring'));
    })
    .sort()
    .map((f) => join('server', 'tests', f));
}

const SLOW = new Set(['lint', 'typecheck']);

/**
 * 收口清单。顺序按「快 → 慢」，失败即停（与 CI 的 bash -e 语义一致）。
 * @param {{root: string, quick?: boolean}} opts 仓库根与 quick 开关
 * @returns {Array<{name:string, cmd:string[]}>} 门禁项（name 唯一、cmd 可直接 spawn）
 */
export function closeGateList({ root, quick = false }) {
  const guards = ['complexity', 'nesting', 'duplication', 'deadcode', 'debt', 'typecoverage'];
  const list = [
    { name: 'complexity', cmd: ['node', 'scripts/complexity-guard.mjs'] },
    ...guards.filter((g) => g !== 'complexity').map((g) => ({ name: g, cmd: ['node', `scripts/${g}-guard.mjs`] })),
    ...guards.map((g) => ({ name: `${g}:selftest`, cmd: ['node', `scripts/${g}-guard.mjs`, '--selftest'] })),
    { name: 'readme', cmd: ['node', 'scripts/readme-consistency.mjs'] },
    { name: 'readme:selftest', cmd: ['node', 'scripts/readme-consistency.mjs', '--selftest'] },
    { name: 'flag:selftest', cmd: ['node', 'scripts/readme-flag-coverage.mjs', '--selftest'] },
    // [D145 2026-10-24] greenguard 此前只在 CI lint 跑、收口清单没有它：D143 的
    // scripts/build-portable.mjs（失败退出委托给 failWith）被判 only-exit-0 恒绿，
    // 本地 gate:close 全绿、CI lint 红。判据本身已修（识别委托 helper）+ 自证。
    { name: 'greenguard', cmd: ['node', 'scripts/greenguard-check.mjs'] },
    { name: 'greenguard:selftest', cmd: ['node', 'scripts/greenguard-check.mjs', '--selftest'] },
    // [D175 2026-10-26] agent 装载面（插件清单 / 技能说明 / .mcp.json）的一致性。
    { name: 'agent-manifest', cmd: ['node', 'scripts/agent-manifest-check.mjs'] },
    { name: 'agent-manifest:selftest', cmd: ['node', 'scripts/agent-manifest-check.mjs', '--selftest'] },
    // [D178 2026-10-26] 质量台账：docs/质量台账.md 必须与脚本产出逐字一致（手改即红）。
    { name: 'quality-ledger', cmd: ['node', 'scripts/quality-ledger.mjs', '--check'] },
    { name: 'quality-ledger:selftest', cmd: ['node', 'scripts/quality-ledger.mjs', '--selftest'] },
    // [D179 2026-10-26] 配方包：没有真机验证不许写 CVE 号；破坏性条目必须 risk 3。
    { name: 'recipes', cmd: ['node', 'scripts/recipe-pack.mjs', '--check'] },
    { name: 'recipes:selftest', cmd: ['node', 'scripts/recipe-pack.mjs', '--selftest'] },
    // [D218 2026-10-31] CHANGELOG 索引：顶部索引表必须等于正文批次（手改/漏更新即红）。
    // 索引本身只是导航，正文一个字不动 —— 防的是「手工维护的索引静默过期」。
    { name: 'changelog-index', cmd: ['node', 'scripts/changelog-index.mjs', '--check'] },
    { name: 'changelog-index:selftest', cmd: ['node', 'scripts/changelog-index.mjs', '--selftest'] },
    // [D182 2026-10-26] npm 包体：体积上限 / 必备资产 / 不含 tests·ledger / 解包后真能跑。
    { name: 'pack-check', cmd: ['node', 'scripts/pack-check.mjs'] },
    { name: 'pack-check:selftest', cmd: ['node', 'scripts/pack-check.mjs', '--selftest'] },
    // [D215 2026-10-31] wiring 加并发上限：默认并发 = CPU 核数，本机 57 个文件同时跑会
    // 因端口/句柄竞争让个别文件 cancelled（实测 12 分钟不返回；`--test-timeout` 报
    // `exploitRoutes.guards.test.js` cancelled，单跑却 7/7 通过）。限 4 后 349/349、8.7s，
    // 且比默认并发更快 —— 门禁跑不完等于没有门禁。
    { name: 'wiring', cmd: ['node', '--test', '--test-concurrency=4', ...wiringTestFiles(root)] },
    { name: 'facts', cmd: ['npm', 'run', '--silent', 'facts:check'] },
    { name: 'refs', cmd: ['node', 'scripts/ref-integrity.mjs'] },
    { name: 'e2e-wiring', cmd: ['node', 'scripts/e2e-wiring-check.mjs'] },
    { name: 'e2e-wiring:selftest', cmd: ['node', 'scripts/e2e-wiring-check.mjs', '--selftest'] },
    // [D143 2026-10-23] 便携包两个脚本的自证（交付件链路判据不能空转；真冒烟属 CI）。
    { name: 'portable-build:selftest', cmd: ['node', 'scripts/build-portable.mjs', '--selftest'] },
    { name: 'portable-smoke:selftest', cmd: ['node', 'scripts/portable-smoke.mjs', '--selftest'] },
    // [D144 2026-10-23] 本机靶场体检判据的自证（纯函数，不探测也不起进程）。
    { name: 'labs:selftest', cmd: ['node', 'scripts/labs.mjs', '--selftest'] },
  ];
  if (quick) return list.filter((g) => !SLOW.has(g.name));
  return [...list, { name: 'typecheck', cmd: ['npm', 'run', '--silent', 'typecheck'] }, { name: 'lint', cmd: ['npm', 'run', '--silent', 'lint'] }];
}
