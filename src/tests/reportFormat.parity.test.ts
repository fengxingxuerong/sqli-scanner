// @vitest-environment node
// ============================================================================
// src/tests/reportFormat.parity.test.ts —— 报告导出格式：前端 UI ↔ useScan ↔ 后端白名单
//
// 为什么必须有（2026-10-03 实测缺口）：
//   `sarif` 在后端早已全链支持——ReportGenerator.toSARIF 有实现、scanRoutes.js 的
//   FORMAT_EXT 白名单收它、content-types 也给了 `application/sarif+json`——但前端
//   `ReportExport.tsx` 的 ExportFormat 联合类型与按钮里都没有它，用户**永远拿不到**
//   GitHub Security / DefectDojo 认的格式。这是本仓反复出现的「能力已实现、某一端取不到」
//   缺陷族（与 scanConfig.contract.test.ts 要防的是同一类，只是作用在导出格式上）。
//
//   更隐蔽的一半：`useScan.exportReport` 用 `mimeMap[format]` 取 MIME。若某格式进了
//   ExportFormat 联合却没进 mimeMap，`mime` 就是 undefined，`saveFile(..., undefined)`
//   在部分环境把产物存成匿名二进制 —— 报告"存下来了但下游打不开"。这类洞靠人记不住。
//
// 三条断言（全部源码级提取，不 import 后端模块图）：
//   ① 前端能请求的格式 ⊆ 后端 FORMAT_EXT 白名单（否则一点就 400）；
//   ② mimeMap 覆盖 ExportFormat 的每一个成员（否则 mime 为 undefined）；
//   ③ 自证：提取器对源文本敏感（在内存副本里删掉一处即抽不到），防止解析空转假绿。
// ============================================================================

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const read = (rel: string) => readFileSync(fileURLToPath(new URL(rel, import.meta.url)), 'utf8');

// ⚠️ 必须先剥注释再抽键：否则把一行 `// sarif: '...'` 注释掉，提取器照样"看到" sarif →
// 断言假绿。这不是假想 —— 本守卫首版就漏了这一步，缺陷注入（注释掉 mimeMap 的 sarif）时
// 四条断言全绿，等于没守住。剥注释后注入才会红（见下方自证用例）。
//
// ⚠️ 顺序：**先行注释、后块注释**。反过来会让注释里出现的 `/x/*`（如 `/exploit/*`）被当成
// 块注释开头，吞掉其后的真实代码（sqlmapConfig.contract.test.ts 首跑就栽过）。
const stripComments = (s: string) =>
  s.replace(/\/\/[^\n]*/g, '').replace(/\/\*[\s\S]*?\*\//g, '');

/** 从 `const NAME = { ... };` 形态的对象字面量里抽出键名（值里的字符串不参与，因为键后必跟 `:`）。 */
function objectKeys(src: string, marker: string, closer: string): string[] {
  const start = src.indexOf(marker);
  if (start < 0) throw new Error(`未找到 ${marker} —— 源码改了形态，本测试需同步`);
  const end = src.indexOf(closer, start + marker.length);
  if (end < 0) throw new Error(`未找到 ${marker} 的收尾 ${closer} —— 本测试需同步`);
  const seg = stripComments(src.slice(start + marker.length, end));
  return [...seg.matchAll(/(?:'([^']+)'|([A-Za-z_][\w-]*))\s*:/g)].map((m) => m[1] ?? m[2]);
}

/** 抽 `export type NAME = 'a' | 'b' | ...;` 的成员。 */
function unionMembers(src: string, marker: string): string[] {
  const start = src.indexOf(marker);
  if (start < 0) throw new Error(`未找到 ${marker} —— 源码改了形态，本测试需同步`);
  const end = src.indexOf(';', start);
  const seg = stripComments(src.slice(start, end));
  return [...seg.matchAll(/'([^']+)'/g)].map((m) => m[1]);
}

const SCAN_ROUTES = read('../../server/src/api/scanRoutes.js');
const REPORT_EXPORT = read('../components/ReportExport.tsx');
const USE_SCAN = read('../hooks/useScan.ts');

const backendFormats = objectKeys(SCAN_ROUTES, 'FORMAT_EXT = {', '};');
const uiFormats = unionMembers(REPORT_EXPORT, 'export type ExportFormat =');
const mimeKeys = objectKeys(USE_SCAN, 'const mimeMap = {', '} as const;');

describe('导出格式契约：UI ↔ useScan ↔ 后端白名单', () => {
  it('自证：提取器非空且对源文本敏感（删/注释掉一处即抽不到），防解析空转假绿', () => {
    // 抽到了东西
    expect(backendFormats.length).toBeGreaterThan(3);
    expect(uiFormats.length).toBeGreaterThan(3);
    expect(mimeKeys.length).toBeGreaterThan(3);
    // 敏感度 ①：在内存副本里把 sarif 从白名单删掉，必须抽不到它
    const deleted = SCAN_ROUTES.replace(/sarif:\s*'sarif'/, '');
    expect(deleted).not.toBe(SCAN_ROUTES);
    expect(objectKeys(deleted, 'FORMAT_EXT = {', '};')).not.toContain('sarif');
    // 敏感度 ②（本守卫首版漏掉、被注入复验抓出的洞）：把一行**注释掉**也必须抽不到 ——
    // 若不剥注释，`// sarif: '...'` 会被当成键存在，断言全线假绿。
    const commented = USE_SCAN.replace(/\n\s*sarif:\s*'[^']*',/, "\n  // sarif: 'application/sarif+json; charset=utf-8',");
    expect(commented).not.toBe(USE_SCAN);
    expect(objectKeys(commented, 'const mimeMap = {', '} as const;')).not.toContain('sarif');
    // 且不得张冠李戴：抽出来的必须真的是格式名，不是 value
    expect(backendFormats).not.toContain('db.json'); // 那是 value，不是 key
  });

  it('① 前端能请求的每个格式，后端 FORMAT_EXT 必须收（否则一点就 400）', () => {
    const notAccepted = uiFormats.filter((f) => !backendFormats.includes(f));
    expect(notAccepted).toEqual([]);
  });

  it('② mimeMap 覆盖 ExportFormat 的每个成员（否则 mime 为 undefined → 产物存成匿名二进制）', () => {
    const missingMime = uiFormats.filter((f) => !mimeKeys.includes(f));
    expect(missingMime).toEqual([]);
  });

  it('③ sarif 回归锚点：后端白名单与前端联合类型都要收它（本次已修的缺口不得回退）', () => {
    expect(backendFormats).toContain('sarif');
    expect(uiFormats).toContain('sarif');
    expect(mimeKeys).toContain('sarif');
  });
});
