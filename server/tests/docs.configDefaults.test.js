// ============================================================================
// docs.configDefaults.test.js —— docs/api.md 的配置表必须与代码同源
// ============================================================================
// 为什么补这一支：本仓的数字口径有 readme:check 盯着 README，但 **docs/api.md 的
// REST 配置表没有任何门禁**。实测后果：defaults.js 里 timeoutMs 早已从 10s 提到 30s、
// retry 从 2 提到 3（[P0-FIX 对标 sqlmap] 那一批），而 api.md 的表还在写
// 「默认 10000」「默认 2」—— 使用者照文档取值，拿到的是与文档相反的默认档，
// 而且这类漂移**只会越攒越多**，因为没人会红。
//
// 判据形态：从表格里抽 `| \`key\` | MIN-MAX（默认 C） |`，两头分别比对
//   ① C === defaults.<key>
//   ② MIN/MAX === sanitizeStart 里该键的 clamp 区间（pickInt(cfg,'key',…,MIN,MAX)）
// 只覆盖「表里写了区间且代码用 pickInt 收敛」的键；③ 钉住最小覆盖面，
// 防止哪天正则失效导致本测试**空转全绿**（这是本仓所有守卫的统一自证要求）。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { defaults as D } from '../src/config/defaults.js';

const API_MD = readFileSync(new URL('../../docs/api.md', import.meta.url), 'utf8');
// 2026-09-25：配置守卫整段搬到 api/scanConfigGuard.js（HTTP 与直连两条入口共用）。
// 文本锚点于是必须覆盖【入口层这一整簇】——只读 scanRoutes 会让本守卫在搬移后
// 静默找不到 clamp 收敛点（那正是它要防的"文档写了不存在的能力"的反面：假红/假绿都可能）。
const ROUTES = readFileSync(new URL('../src/api/scanRoutes.js', import.meta.url), 'utf8') + readFileSync(new URL('../src/api/scanConfigGuard.js', import.meta.url), 'utf8');

// 表格行：`| \`timeoutMs\` | 1000-60000（默认 30000） | 说明 |`（区间可省略，默认值必须有）
const ROW_RE = /^\|\s*`([A-Za-z][A-Za-z0-9_]*)`\s*\|\s*(?:(\d+)\s*-\s*(\d+))[^|]*（默认\s*(\d+)）/gm;

/** 从 sanitizeStart 里取某键的 pickInt 第三参（clamp 默认值）；取不到返回 undefined */
function clampDefault(key) {
  const m = ROUTES.match(new RegExp(`pickInt\\(\\s*cfg\\s*,\\s*'${key}'\\s*,\\s*(defaults\\.${key}|\\d+)\\s*,\\s*(-?\\d+)\\s*,\\s*(-?\\d+)\\s*\\)`));
  if (!m) return undefined;
  return m[1].startsWith('defaults.') ? D[key] : Number(m[1]);
}

/** 从 sanitizeStart 里取某键的 pickInt 区间；取不到返回 null（该键不参与区间比对） */
function clampRange(key) {
  const m = ROUTES.match(new RegExp(`pickInt\\(\\s*cfg\\s*,\\s*'${key}'\\s*,\\s*[^,]+\\s*,\\s*(-?\\d+)\\s*,\\s*(-?\\d+)\\s*\\)`));
  return m ? [Number(m[1]), Number(m[2])] : null;
}

test('docs/api.md 配置表的默认值与 clamp 区间必须与代码一致（防文档口径腐烂）', () => {
  const rows = [...API_MD.matchAll(ROW_RE)];
  assert.ok(rows.length >= 6, `只从 api.md 抽出 ${rows.length} 行带默认值的配置项 —— 表格格式变了？本守卫不得空转`);
  const problems = [];
  for (const [, key, minS, maxS, defS] of rows) {
    const docDefault = Number(defS);
    // 默认值的家要么在 defaults.js，要么在 sanitizeStart 的 clamp 第三参（两处都没有
    // 就是"文档写了不存在的能力"）。dumpMaxRows 属于后者 —— 它刻意不进 defaults：
    // CLI 路径不经过 sanitizeStart，键缺席时 Extractor.js:305 走 `lim * 50` 的联动兜底，
    // 补进 defaults 会把两条入口的实际上限改得一样，那是行为变化而不是文档修复。
    const codeDefault = key in D ? D[key] : clampDefault(key);
    if (codeDefault === undefined) {
      problems.push(`${key}：docs 有此项，但 defaults.js 与 sanitizeStart 的 clamp 默认值都没有（文档写了不存在的能力）`);
      continue;
    }
    if (codeDefault !== docDefault) {
      problems.push(`${key}：docs/api.md 写「默认 ${docDefault}」，代码实为 ${JSON.stringify(codeDefault)}`);
    }
    if (minS === undefined) continue; // 只写了默认值的行不比区间
    const range = clampRange(key);
    if (!range) {
      problems.push(`${key}：docs 写区间 ${minS}-${maxS}，但 sanitizeStart 里没有对应的 pickInt 收敛点`);
      continue;
    }
    if (range[0] !== Number(minS) || range[1] !== Number(maxS)) {
      problems.push(`${key}：docs 写区间 ${minS}-${maxS}，代码实际 clamp 到 ${range[0]}-${range[1]}`);
    }
  }
  assert.deepEqual(problems, [], `docs/api.md 与代码口径不一致：\n  ${problems.join('\n  ')}`);
});
