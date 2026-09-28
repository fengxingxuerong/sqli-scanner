// ============================================================================
// core/loadEnv.js —— 在**任何**业务模块求值之前把 .env 读进 process.env
//
// 为什么单独成模块：ESM 的 import 会先于模块体执行，而 index.js 原来把
// `dotenv.config()` 写在 import 语句之后 —— 于是被 import 的模块在**加载期**读的
// 环境变量，全部看不到 .env 里的值。实际后果：
//   · server/.env 配了 EXPLOIT_ENABLED=1，/exploit/* 仍 403（该键在 exploitRoutes
//     加载期取值），而 .env.example 第 28 行恰恰把这个键当作正式配置项在推荐；
//   · 同类的"改了 .env 不生效、只能靠真实进程 env"的困惑会一路查到引擎里去。
// 用法：index.js 的**第一条** import。dotenv 默认不覆盖已存在的变量，
//       因此"进程 env > server/.env > 仓库根 .env"的优先级是稳定的。
// ============================================================================
import { config as loadDotenv } from 'dotenv';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));

// server/.env（`npm run server` = cd server && node index.js 的形态）
// 仓库根 .env（`node server/index.js` 从根目录起的形态，Docker 也走这一层）
for (const p of [resolve(HERE, '../../.env'), resolve(HERE, '../../../.env')]) {
  loadDotenv({ path: p });
}
