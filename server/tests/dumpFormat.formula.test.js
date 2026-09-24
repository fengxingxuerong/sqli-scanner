// ============================================================================
// dumpFormat.formula.test.js —— 拖库 CSV 导出的公式注入防护（服务端两处实现）
// ============================================================================
// 存在理由：dumpFormat 的输入是**从目标数据库拖出来的行**，单元格值全部由被扫系统决定。
// 测试者会把导出件用 Excel/WPS 打开，而以 `= + - @ \t \r` 开头的单元格会被电子表格
// 当作公式求值 —— 也就是说，被扫的那台机器可以隔着一条数据库记录，把命令送到
// 安全工程师的办公套件里执行。扫描器不能成为把敌意数据送进 Office 的通道。
//
// 项目里本来就有这道守卫：ReportGenerator.csvSafeCell 做了前缀防护
// （reportGenerator.fields.test.js:74 钉住），但**同职责的另两处漏了**：
//   · server/src/engine/dumpFormat.js escapeCsvCell —— 拖库 CSV 的权威实现（Extractor 走它）
//   · src/shared/dumpExport.ts csvCell —— 前端「导出拖库数据」按钮走它
// 三处同源只有一处有守卫，属「文档承诺 ≠ 接线」的老病根（见 TODO L/U/Q 条）。
// 行为契约在本文件与 src/tests/csvFormulaParity.test.ts 各自验一遍，
// 后者再从三份源码里抽前缀正则做字面量比对，防止四舍五入式的漂移。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { escapeCsvCell, formatDumpData } from '../src/engine/dumpFormat.js';

const DDE = `=cmd|'/c calc'!A1`;

test('escapeCsvCell：= 开头的敌意值加单引号前缀（Excel 不再按公式解析）', () => {
  assert.equal(escapeCsvCell(DDE), `'${DDE}`);
});

test('escapeCsvCell：+ - @ 以及制表/回车开头同样受护', () => {
  for (const lead of ['+', '-', '@', '\t', '\r']) {
    const out = escapeCsvCell(`${lead}SUM(1,2)`);
    // 该值含逗号，所以外层还会有 CSV 包裹引号；剥掉包裹引号后必须以 ' 开头
    assert.ok(out.replace(/^"/, '').startsWith("'"), `前缀 ${JSON.stringify(lead)} 未受护：${JSON.stringify(out)}`);
  }
});

test('escapeCsvCell：加前缀后原有的结构转义不丢（含逗号仍需整体包裹）', () => {
  // 顺序很重要：先判公式再判包裹，否则会产出未包裹的 `'a,b` —— 逗号把单元格切开
  assert.equal(escapeCsvCell('=a,b'), `"'=a,b"`);
  assert.equal(escapeCsvCell('@x"y'), `"'@x""y"`);
});

test('escapeCsvCell：正常数据不得被误伤（负数/文本/首尾空格行为保持原契约）', () => {
  assert.equal(escapeCsvCell('abc'), 'abc');
  assert.equal(escapeCsvCell('123'), '123');
  assert.equal(escapeCsvCell('a b'), 'a b');
  assert.equal(escapeCsvCell(' a '), '" a "');
  assert.equal(escapeCsvCell(null), '');
  assert.equal(escapeCsvCell(0), '0');
  // 已知取舍：以 `-`/`+` 开头的**文本**值（如 -5、+86 手机号）会被降级成文本单元格。
  // 与 ReportGenerator 同口径，宁可少一次求值，不赌「这个值看起来无害」。
  assert.equal(escapeCsvCell('-5'), `'-5`);
});

test('formatDumpData(csv)：整表导出里敌意单元格全部受护', () => {
  const csv = formatDumpData(
    [{ username: DDE, note: '@SUM(1,2)', ok: 'plain' }],
    ['username', 'note', 'ok'],
    'appdb.users',
    'csv'
  );
  const lines = csv.split('\n');
  assert.ok(lines[1].includes(`'${DDE}`), `数据行未受护：${lines[1]}`);
  assert.ok(lines[1].includes(`'@SUM(1,2)`), `@ 前缀未受护：${lines[1]}`);
  assert.ok(lines[1].includes('plain'), '正常值被误伤');
});

test('formatDumpData(csv)：表头同样受护（列名也是目标库可控数据）', () => {
  const csv = formatDumpData([{ [DDE]: 'v' }], [DDE], 't', 'csv');
  assert.ok(csv.split('\n')[0].includes(`'${DDE}`), `表头未受护：${csv}`);
});

test('formatDumpData(csv)：空数据骨架分支的表头也受护（走的是同一个 escapeCsvCell）', () => {
  const csv = formatDumpData([], [DDE, 'b'], 't', 'csv');
  assert.equal(csv, `'${DDE},b`);
});
