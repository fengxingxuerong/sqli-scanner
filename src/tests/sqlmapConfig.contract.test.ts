// @vitest-environment node
// ============================================================================
// src/tests/sqlmapConfig.contract.test.ts —— sqlmap 桥接链的三段契约
//
//   前端面板 SqlmapOptions ──patch──▶ SqlmapConfig(types.ts) ──POST──▶ 后端
//        sqlmapBridge.buildArgs（`c.<key>` 读配置）
//
// 为什么必须有（2026-10-03 实测抓到一个真缺陷）：
//   `retry` 这个键在**三段里各有一个域**：面板允许 0（`Math.max(0,·)`）、类型注释写
//   「0 表示不重试」、内置引擎也真支持 0（Slider min=0 + core/http/retry.js 明处理 retry=0）——
//   但 `sqlmapBridge.buildArgs` 却写 `retry >= 1`，把 0 与负值一起丢弃 ⇒ 省略 `--retries`
//   ⇒ sqlmap 回落**默认 3 次重试**。用户「不重试」的意图被静默推翻，而**没有任何测试会红**
//   （后端只测了自己的边界，前端只测了渲染）。
//
//   这正是本仓反复复发的那族：**同一语义两份实现，只改/只测了一处**（对照
//   scanConfig.contract.test.ts 要防的「面板键 → 请求体 → 后端白名单」）。
//   sqlmap 桥接这条链此前**完全没有契约守卫**，本文件补上。
//
// 三条断言（源码级提取，不 import 后端模块图）：
//   ① 每个 `SqlmapConfig` 键都被 `buildArgs` 真正读取（否则面板有控件 = 静默 no-op）；
//   ② 每个 `SqlmapConfig` 键在面板里都有控件（否则类型里加了键、用户永远设不了）；
//   ③ 自证：提取器非空、剥注释、对源文本敏感（防解析空转假绿）。
// ============================================================================

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const read = (rel: string) => readFileSync(fileURLToPath(new URL(rel, import.meta.url)), 'utf8');

// ⚠️ 先剥注释再抽键，否则把一行 `// retry: ...` 注释掉后提取器照样"看到"它 → 断言假绿。
// （此教训在 reportFormat.parity.test.ts 首版栽过；这里直接带上。）
//
// ⚠️⚠️ **顺序必须是「先行注释、后块注释」**（2026-10-03 本文件首跑就栽在这）：
// sqlmapBridge 的注释里有一句 `... 与内置引擎的 /exploit/* 是同一个 ...`。若先跑块注释正则
// `/\/\*[\s\S]*?\*\//`，那个 `/exploit/*` 里的 `/*` 会被当成块注释开头，一直吞到下一处 `*/`
// —— 把紧随其后的 243–254 行（`c.osShell` / `c.fileRead` 的真正消费点）整段删掉，
// 于是断言 ① 误报「这两个键没被读取」。先剥行注释能把整条 `// ... /exploit/* ...` 抹掉，
// 不留游离的 `/*`，块注释正则才安全。
const stripComments = (s: string) =>
  s.replace(/\/\/[^\n]*/g, '').replace(/\/\*[\s\S]*?\*\//g, '');

/** `SqlmapConfig` 接口声明的键 = 前端可写域 */
function sqlmapConfigKeys(src: string): string[] {
  const start = src.indexOf('export interface SqlmapConfig {');
  if (start < 0) throw new Error('未找到 SqlmapConfig —— 类型改了形态，本测试需同步');
  const end = src.indexOf('\n}', start);
  if (end < 0) throw new Error('未找到 SqlmapConfig 的收尾 —— 本测试需同步');
  const body = stripComments(src.slice(start, end));
  return [...body.matchAll(/^\s{2}([A-Za-z_][\w]*)\??\s*:/gm)].map((m) => m[1]);
}

/** `buildArgs` 实际读取的配置键（`c.<key>`，c = input.config.sqlmap） */
function buildArgsConsumedKeys(src: string): string[] {
  const start = src.indexOf('export function buildArgs(');
  if (start < 0) throw new Error('未找到 buildArgs —— 源码改了形态，本测试需同步');
  const end = src.indexOf('export class SqlmapBridge', start);
  if (end < 0) throw new Error('未找到 buildArgs 的收尾（SqlmapBridge 类）—— 本测试需同步');
  const body = stripComments(src.slice(start, end));
  return [...new Set([...body.matchAll(/\bc\.([A-Za-z_][\w]*)/g)].map((m) => m[1]))];
}

/** 面板实际会写的补丁键（`onChange({ <key>: ... })`） */
function panelPatchKeys(src: string): string[] {
  const body = stripComments(src);
  return [...new Set([...body.matchAll(/onChange\(\{\s*([A-Za-z_][\w]*)\s*:/g)].map((m) => m[1]))];
}

const TYPES = read('../shared/types.ts');
const BRIDGE = read('../../server/src/engine/sqlmapBridge.js');
const PANEL = read('../components/SqlmapOptions.tsx');

const cfgKeys = sqlmapConfigKeys(TYPES);
const consumed = buildArgsConsumedKeys(BRIDGE);
const patched = panelPatchKeys(PANEL);

describe('sqlmap 桥接链契约：面板 ⇄ SqlmapConfig ⇄ buildArgs', () => {
  it('自证：提取器非空且对源文本敏感（删/注释一处即抽不到），防解析空转假绿', () => {
    expect(cfgKeys.length).toBeGreaterThan(15);
    expect(consumed.length).toBeGreaterThan(15);
    expect(patched.length).toBeGreaterThan(15);
    // 删除敏感度
    const deleted = BRIDGE.replace(/c\.excludeSysdbs === true/, '');
    expect(deleted).not.toBe(BRIDGE);
    expect(buildArgsConsumedKeys(deleted)).not.toContain('excludeSysdbs');
    // 注释敏感度（首版栽过的洞）
    const commented = TYPES.replace(/\n\s*retry: number;/, "\n  // retry: number;");
    expect(commented).not.toBe(TYPES);
    expect(sqlmapConfigKeys(commented)).not.toContain('retry');
    // 块注释陷阱自证：行注释里的 `/exploit/*` 不许触发块注释、吞掉其后的代码
    const trap = '// see /exploit/* here\nconst c = { osShell: 1, fileRead: 2 };';
    expect(stripComments(trap)).toContain('osShell');
    expect(stripComments(trap)).toContain('fileRead');
  });

  it('① 每个 SqlmapConfig 键都必须被 buildArgs 读取（否则面板有控件 = 静默 no-op）', () => {
    const ignored = cfgKeys.filter((k) => !consumed.includes(k));
    expect(
      ignored,
      `这些键前端能设、SqlmapConfig 里也有，但 sqlmapBridge.buildArgs 从不读 ⇒ 用户设了等于没设：${ignored.join(', ')}`
    ).toEqual([]);
  });

  it('② 每个 SqlmapConfig 键都必须有面板控件（否则类型里加了键、用户永远设不了）', () => {
    const noControl = cfgKeys.filter((k) => !patched.includes(k));
    expect(
      noControl,
      `这些键在 types.ts 里声明了，但 SqlmapOptions 面板没有对应控件：${noControl.join(', ')}`
    ).toEqual([]);
  });

  it('③ 回归锚点：retry 必须三段都在（2026-10-03 修的 retry=0 缺口不得回退）', () => {
    expect(cfgKeys).toContain('retry');
    expect(consumed).toContain('retry');
    expect(patched).toContain('retry');
  });
});
