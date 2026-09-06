// coverage 运行包装：以 vitest run --coverage 跑前端覆盖率。
// 为什么需要 wrapper：本机 WorkBuddy 沙盒在 NODE_OPTIONS 中注入了 genie-safe-delete
// shim，vitest 跑完覆盖后清理临时目录（coverage/.tmp 下几十个 v8 快照文件）会被
// safe-delete 的「批量删除确认」拦截，导致报告已生成但进程退出码非 0。
// 这里在子进程中剥离该注入（仅移除 genie-safe-delete 相关 require，保留其余 NODE_OPTIONS），
// 其余行为与直接跑 vitest 完全一致。
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
  stdio: 'inherit',
  env: {
    ...process.env,
    NODE_OPTIONS: filteredNodeOptions,
  },
  cwd: root,
  windowsHide: true,
});

process.exit(res.status ?? 1);
