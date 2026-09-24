// ============================================================================
// src/tests/csvFormulaParity.test.ts —— CSV 公式注入防护的三处同源契约
// ============================================================================
// 存在理由（2026-09-24）：把敌意数据写进电子表格能执行公式，是本项目的交付面之一 ——
// 拖库结果里的每个单元格值都由**被扫系统**决定，测试者习惯把 CSV 导进 Excel/WPS 排版。
// `=cmd|'/c calc'!A1` 这样的值落在 `username` 列里，打开即触发。
//
// 同一个「CSV 单元格转义」在项目里有**三份独立实现**：
//   ① server/src/services/ReportGenerator.js  csvSafeCell      （扫描报告 CSV）
//   ② server/src/engine/dumpFormat.js         escapeCsvCell     （拖库 CSV，Extractor 走它）
//   ③ src/shared/dumpExport.ts                csvCell           （前端「导出拖库数据」按钮）
// 历史上只有 ① 做了公式前缀防护（server/tests/reportGenerator.fields.test.js 钉住），
// ②③ 只做了引号/逗号转义 —— 于是「报告导出安全、拖库导出危险」，而后者才是真正
// 装着目标数据的那一份。这类断口的成因不是没想到，是**三份各写各的、没人对齐**。
//
// 本测试不抄录任何一份的值，而是从三份源码里抽 `FORMULA_PREFIX_RE` 的字面量比对：
// 任一侧改正则、改名、删掉守卫，这里立刻红，并指名是哪一处。
// 行为侧再各自验一遍（②③ 的服务端行为在 server/tests/dumpFormat.formula.test.js）。
// ============================================================================

// 本文件只读源码文本 + 调纯函数，不需要 DOM
// @vitest-environment node
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dumpToCsv, tableToCsv } from '../shared/dumpExport';
import type { ExtractedData } from '../shared/types';

const read = (rel: string) => readFileSync(fileURLToPath(new URL(rel, import.meta.url)), 'utf8');

/** 从源码里抽出 FORMULA_PREFIX_RE 的声明字面量（找不到就抛错指名文件） */
function prefixLiteralOf(file: string): string {
  const src = read(file);
  const line = src.split('\n').find((l) => /const\s+FORMULA_PREFIX_RE\s*=/.test(l));
  if (!line) {
    throw new Error(`${file} 里没有 FORMULA_PREFIX_RE 声明 —— 公式前缀守卫被删掉或改名了`);
  }
  const mm = /=\s*(\/.+\/[a-z]*)/.exec(line);
  if (!mm) throw new Error(`${file} 的 FORMULA_PREFIX_RE 不是正则字面量，抽不出来：${line.trim()}`);
  return mm[1];
}

const SOURCES = [
  '../../server/src/services/ReportGenerator.js',
  '../../server/src/engine/dumpFormat.js',
  '../shared/dumpExport.ts',
];

// 电子表格公式注入载荷：DDE 攻击向量，Excel/WPS 会尝试求值
const DDE = `=cmd|'/c calc'!A1`;

describe('csvFormulaParity: 三处前缀守卫同源', () => {
  it('三份实现里的 FORMULA_PREFIX_RE 是同一个字面量', () => {
    const literals = SOURCES.map((f) => [f, prefixLiteralOf(f)] as const);
    const [firstFile, first] = literals[0];
    for (const [file, lit] of literals.slice(1)) {
      expect(lit, `${file} 的前缀集与 ${firstFile} 不一致`).toBe(first);
    }
  });

  it('守卫的前缀集必须真的覆盖 = + - @ \\t \\r（防止有人把正则改成空匹配来骗过比对）', () => {
    const lit = prefixLiteralOf('../shared/dumpExport.ts');
    const re = new RegExp(lit.slice(1, lit.lastIndexOf('/')));
    for (const lead of ['=', '+', '-', '@', '\t', '\r']) {
      expect(re.test(`${lead}SUM(1)`), `前缀 ${JSON.stringify(lead)} 不在守卫集里`).toBe(true);
    }
    // 反向：普通字符不得命中，否则一切单元格都被加前缀 = 数据全被误伤
    for (const benign of ['a', '1', ' ', '#', '"']) {
      expect(re.test(`${benign}x`), `普通前缀 ${JSON.stringify(benign)} 被误判成公式`).toBe(false);
    }
  });
});

describe('csvFormulaParity: 前端 dumpExport 的行为', () => {
  const DATA = {
    databases: ['appdb'],
    tables: { appdb: ['users'] },
    columns: { 'appdb.users': ['username:varchar', 'note:varchar'] },
    rows: {
      'appdb.users': [
        { username: DDE, note: '@SUM(1,2)' },
        { username: 'alice', note: 'plain' },
      ],
    },
  } as unknown as ExtractedData;

  it('dumpToCsv：数据行的敌意单元格被降级为文本', () => {
    const csv = dumpToCsv(DATA);
    const line = csv.split('\n').find((l) => l.includes('calc'));
    expect(line, '未找到 DDE 所在行').toBeDefined();
    // 值本身含单引号但没有逗号/双引号 → 只加前缀、不整体包裹
    expect(line).toContain(`'=cmd|'/c calc'!A1`);
    // @SUM(1,2) 含逗号 → 前缀之外还要整体包裹，否则逗号把单元格切开
    expect(line).toContain(`"'@SUM(1,2)"`);
  });

  it('dumpToCsv：不再存在任何以公式前缀开头的裸单元格', () => {
    const csv = dumpToCsv(DATA);
    expect(csv).toContain('alice');
    expect(csv).toContain('plain');
    const row = csv.split('\n').find((l) => l.includes('calc'))!;
    // 逐格起点检查：每格（行首或逗号之后，允许可选的 CSV 包裹引号）都不得直接以公式前缀开头
    expect(row).not.toMatch(/(^|,)"?[=+\-@]/);
    expect(row).toMatch(/(^|,)"?'/);
  });

  it('dumpToCsv：表头同样过守卫（列名也是目标库可控数据）', () => {
    const hostile = {
      databases: [],
      tables: {},
      columns: {},
      rows: { 'appdb.t': [{ [DDE]: 'v' }] },
    } as unknown as ExtractedData;
    const csv = dumpToCsv(hostile);
    const header = csv.split('\n').find((l) => l.includes('calc'));
    expect(header).toMatch(/'=/);
  });

  it('tableToCsv：数据与表头都受护，且正常导出格式不变', () => {
    const csv = tableToCsv(DATA, 'appdb.users');
    expect(csv.startsWith('﻿')).toBe(true);
    expect(csv).toContain('username,note');
    expect(csv).toContain(`'${DDE}`);
    expect(csv).toContain('alice');
  });

  it('不误伤：无公式前缀的普通拖库结果逐字保持', () => {
    const plain = {
      databases: ['appdb'],
      tables: {},
      columns: {},
      rows: { 'appdb.users': [{ id: 1, name: 'o\'brien, x' }] },
    } as unknown as ExtractedData;
    const csv = dumpToCsv(plain);
    expect(csv).toContain('id,name');
    expect(csv).toContain(`"o'brien, x"`);
  });
});
