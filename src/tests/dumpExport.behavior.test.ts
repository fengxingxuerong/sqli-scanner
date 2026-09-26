// ============================================================================
// src/tests/dumpExport.behavior.test.ts —— 前端拖库导出的行为级断言
// ============================================================================
// 与 csvFormulaParity.test.ts 的分工：那份比的是「三处实现的正则字面量是否同源」
// （改了正则就红），这份测的是**这一处实现的行为**——导出的每个单元格到底长什么样。
//
// 为什么值得单独补：dumpExport 是「拖库结果 → 用户桌面」的最后一跳，
// 单元格值 100% 来自被扫数据库（攻击者可控）。它的 branch 覆盖只有 70.6%，
// 未覆盖的恰好是：公式前缀的逐个形态、null/undefined 落空、空表与无列表的跳过、
// 列名含逗号/引号的表头、单表导出的列名切分（"id:INTEGER"）。
// 这些改坏不会报错，只会悄悄产出一份「能打开但列串了 / 打开就执行公式」的 CSV。
// ============================================================================

// 纯函数，不需要 DOM
// @vitest-environment node
import { describe, it, expect } from 'vitest';
import { hasDumpData, dumpToCsv, dumpToJson, tableToCsv, tableToJson } from '../shared/dumpExport';
import type { ExtractedData } from '../shared/types';

const data = (o: Partial<ExtractedData>): ExtractedData =>
  ({ databases: [], tables: {}, columns: {}, rows: {}, ...o }) as ExtractedData;

describe('hasDumpData：有没有拖库数据', () => {
  it('null / undefined / 全空 → false（不能让「没拖到」显示出导出按钮）', () => {
    expect(hasDumpData(null)).toBe(false);
    expect(hasDumpData(undefined)).toBe(false);
    expect(hasDumpData(data({}))).toBe(false);
  });

  it('databases / tables / rows 任一非空 → true（三者各自都能单独成立）', () => {
    expect(hasDumpData(data({ databases: ['appdb'] }))).toBe(true);
    expect(hasDumpData(data({ tables: { appdb: ['users'] } }))).toBe(true);
    expect(hasDumpData(data({ rows: { 'appdb.users': [{ id: 1 }] } }))).toBe(true);
    // 只有 columns 不算数据（没行也没表 = 没拖到东西）
    expect(hasDumpData(data({ columns: { 'appdb.users': ['id'] } }))).toBe(false);
  });
});

describe('dumpToCsv：整体形态', () => {
  it('带 BOM 前缀（Office 打开中文不乱码）', () => {
    const csv = dumpToCsv(data({ rows: { 'appdb.users': [{ id: 1 }] } }));
    expect(csv.startsWith('\uFEFF')).toBe(true);
  });

  it('库清单行 + 每表区块（## 库.表 → 表头 → 行）', () => {
    const csv = dumpToCsv(
      data({
        databases: ['appdb', 'shop'],
        rows: { 'appdb.users': [{ id: 1, name: 'a' }] },
      }),
    );
    expect(csv).toContain('# 数据库: appdb, shop');
    expect(csv).toContain('## appdb.users');
    expect(csv).toContain('id,name');
    expect(csv).toContain('1,a');
  });

  it('空表与「首行无列」的表跳过（不产出空区块）', () => {
    const csv = dumpToCsv(
      data({
        rows: { 'appdb.empty': [], 'appdb.nocols': [{}], 'appdb.ok': [{ id: 1 }] },
      }),
    );
    expect(csv).not.toContain('## appdb.empty');
    expect(csv).not.toContain('## appdb.nocols');
    expect(csv).toContain('## appdb.ok');
  });

  it('列名本身也过转义（列名同样来自目标库，含逗号会切列、= 开头是公式）', () => {
    const csv = dumpToCsv(data({ rows: { t: [{ '=cmd': 1, 'a,b': 2 }] } }));
    expect(csv).toContain("'=cmd");
    expect(csv).toContain('"a,b"');
  });
});

describe('csvCell：公式注入防护（每个前缀形态都要挡）', () => {
  it('= + - @ TAB CR 开头的值都被加前导单引号', () => {
    const csv = dumpToCsv(
      data({
        rows: {
          t: [
            { a: '=cmd|\'/c calc\'!A1' },
            { a: '+SUM(1)' },
            { a: '-1+2' },
            { a: '@import' },
            { a: '\tleading-tab' },
            { a: '\rleading-cr' },
          ],
        },
      }),
    );
    for (const guarded of ["'=cmd", "'+SUM", "'-1+2", "'@import", "'\tleading-tab", "'\rleading-cr"]) {
      expect(csv).toContain(guarded);
    }
  });

  it('普通文本不加前导引号（不能为了安全把正常数据也改掉）', () => {
    const csv = dumpToCsv(data({ rows: { t: [{ a: 'alice' }, { a: '123' }, { a: 'a-b' }] } }));
    expect(csv).toContain('alice');
    expect(csv).toContain('123');
    expect(csv).toContain('a-b'); // 中间的 '-' 不是前缀，不该被改
    expect(csv).not.toContain("'alice");
  });

  it('含逗号 / 引号 / 换行 → 加引号包裹且内部引号翻倍', () => {
    const csv = dumpToCsv(data({ rows: { t: [{ a: 'a,b' }, { a: 'say "hi"' }, { a: 'line1\nline2' }] } }));
    expect(csv).toContain('"a,b"');
    expect(csv).toContain('"say ""hi"""');
    expect(csv).toContain('"line1\nline2"');
  });

  it('null / undefined → 空单元格（不是 "null" / "undefined" 字符串）', () => {
    const csv = dumpToCsv(data({ rows: { t: [{ a: null, b: undefined, c: 'x' }] } }));
    expect(csv).toContain(',,x');
    expect(csv).not.toContain('null');
    expect(csv).not.toContain('undefined');
  });
});

describe('dumpToJson', () => {
  it('原样结构化输出（带 2 空格缩进，供人读）', () => {
    const json = dumpToJson(data({ databases: ['appdb'] }));
    expect(JSON.parse(json).databases).toEqual(['appdb']);
    expect(json).toContain('\n  ');
  });
});

describe('tableToCsv：单表导出', () => {
  it('列定义 "id:INTEGER" 取冒号前的列名', () => {
    const csv = tableToCsv(
      data({ columns: { 'appdb.users': ['id:INTEGER', 'name:TEXT'] }, rows: { 'appdb.users': [{ id: 1, name: 'a' }] } }),
      'appdb.users',
    );
    expect(csv.split('\n')[0].replace('\uFEFF', '')).toBe('id,name');
    expect(csv).toContain('1,a');
  });

  it('行里缺列 → 空单元格；无 rows → 只有表头', () => {
    const csv = tableToCsv(
      data({ columns: { t: ['id', 'name'] }, rows: { t: [{ id: 1 }] } }),
      't',
    );
    expect(csv).toContain('1,');
    const empty = tableToCsv(data({ columns: { t: ['id'] } }), 't');
    expect(empty.replace('\uFEFF', '').trim()).toBe('id');
  });

  it('列名带逗号照样包引号（单表路径也走同一套转义）', () => {
    const csv = tableToCsv(data({ columns: { t: ['a,b'] }, rows: { t: [{ 'a,b': 1 }] } }), 't');
    expect(csv).toContain('"a,b"');
  });
});

describe('tableToJson：单表切片', () => {
  it('库.表 拆分出 database / table', () => {
    const out = JSON.parse(tableToJson(data({ columns: { 'appdb.users': ['id'] }, rows: { 'appdb.users': [{ id: 1 }] } }), 'appdb.users'));
    expect(out.database).toBe('appdb');
    expect(out.table).toBe('users');
    expect(out.columns).toEqual(['id']);
    expect(out.rows).toEqual([{ id: 1 }]);
  });

  it('无点号 → database 为空串（SQLite 裸表名，不臆造库名）', () => {
    const out = JSON.parse(tableToJson(data({ rows: { users: [{ id: 1 }] } }), 'users'));
    expect(out.database).toBe('');
    expect(out.table).toBe('users');
  });

  it('缺 columns / rows → 空数组而不是 undefined（调用方不必到处兜底）', () => {
    const out = JSON.parse(tableToJson(data({}), 'appdb.users'));
    expect(out.columns).toEqual([]);
    expect(out.rows).toEqual([]);
  });
});
