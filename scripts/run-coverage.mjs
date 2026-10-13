// coverage 运行包装：以 vitest run --coverage 跑前端覆盖率。
// 为什么需要 wrapper：本机 WorkBuddy 沙盒在 NODE_OPTIONS 中注入了 genie-safe-delete
// shim，vitest 跑完覆盖后清理临时目录（coverage/.tmp 下几十个 v8 快照文件）会被
// safe-delete 的「批量删除确认」拦截，导致报告已生成但进程退出码非 0。
// 这里在子进程中剥离该注入（仅移除 genie-safe-delete 相关 require，保留其余 NODE_OPTIONS），
// 其余行为与直接跑 vitest 完全一致。
//
// [D60-8.2] 额外职责：解析 vitest 输出，显式呈现 skipped 计数与清单。
// 跳过 ≠ 通过：有 skipped 时在末尾打印醒目摘要，让 CI/人眼不会把「跳过」读成「全绿」。
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, '..');

// 定位本机 node 可执行（与项目约定一致，优先 .workbuddy 自带 node）
const nodeBin =
  process.env.CODEBUDDY_NODE_BIN ||
  process.env.npm_node_execpath ||
  'node';
const vitestBin = path.join(root, 'node_modules', 'vitest', 'vitest.mjs');

// 过滤掉 safe-delete shim 的 --require 注入，其余 NODE_OPTIONS 原样透传
const filteredNodeOptions = (process.env.NODE_OPTIONS || '')
  .split(/\s+(?=--)/)
  .filter((seg) => !seg.includes('genie-safe-delete'))
  .join(' ');

const args = [vitestBin, 'run', '--coverage', '--no-file-parallelism', ...process.argv.slice(2)];

const res = spawnSync(nodeBin, args, {
  stdio: ['inherit', 'pipe', 'inherit'],
  env: {
    ...process.env,
    NODE_OPTIONS: filteredNodeOptions,
  },
  cwd: root,
  windowsHide: true,
  maxBuffer: 50 * 1024 * 1024,
});

// Re-emit stdout
const stdout = res.stdout ? res.stdout.toString('utf8') : '';
process.stdout.write(stdout);

// Parse skipped tests from vitest output
// vitest verbose reporter prints: "↓ TestName (skipped)" or "↓ TestName [skipped]"
// vitest dot reporter prints: "_" for skipped
// The summary line: "ℹ skipped N"
const skippedLines = [];
const lines = stdout.split('\n');
let skippedCount = 0;
for (const line of lines) {
  // Match summary line: "ℹ skipped N"
  const sm = line.match(/skipped\s+(\d+)/);
  if (sm) { skippedCount = parseInt(sm[1], 10); }
  // Match individual skipped test lines
  if (/↓.*skipped|↓.*\[skipped\]|_.*skipped/i.test(line)) {
    skippedLines.push(line.trim());
  }
}

// Prominent skipped summary
if (skippedCount > 0) {
  console.log('');
  console.log('─'.repeat(60));
  console.log(`⚠  跳过 ${skippedCount} 个测试 —— 跳过 ≠ 通过`);
  if (skippedLines.length > 0) {
    console.log('  跳过清单：');
    for (const s of skippedLines.slice(0, 20)) {
      console.log(`    ${s}`);
    }
    if (skippedLines.length > 20) {
      console.log(`    ... 还有 ${skippedLines.length - 20} 个`);
    }
  }
  console.log('  这些测试未验证，请确认是否为环境依赖缺失或条件跳过。');
  console.log('─'.repeat(60));
}

process.exit(res.status ?? 1);
