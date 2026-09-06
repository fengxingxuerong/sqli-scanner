// S7/G15 单表数据导出测试：
//   ① dumpExport 纯函数：tableToCsv（首行表头=列名 + 转义）、tableToJson（结构化切片）
//   ② DbTree UI：表节点行尾有「导出 CSV / JSON」按钮，点击经 tauriBridge.saveFile 落盘
//      （Web 版即 Blob+a[download] 下载），点按钮不触发节点折叠
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import DbTree from '../components/DbTree';
import { tableToCsv, tableToJson } from '../shared/dumpExport';
import type { ExtractedData } from '../shared/types';

// mock tauriBridge：断言单表导出的落盘调用（文件名 / 内容 / MIME）
vi.mock('../shared/tauriBridge', () => ({
  tauriBridge: { saveFile: vi.fn().mockResolvedValue(undefined), isTauri: false },
}));
import { tauriBridge } from '../shared/tauriBridge';

const DATA: ExtractedData = {
  databases: ['appdb'],
  tables: { appdb: ['users'] },
  columns: { 'appdb.users': ['id:INTEGER', 'name:TEXT'] },
  rows: {
    'appdb.users': [
      { id: 1, name: 'Alice, "Admin"' },
      { id: 2, name: 'Line1\nLine2' },
      { id: 3, name: 'Bob' },
    ],
  },
};

beforeEach(() => {
  vi.mocked(tauriBridge.saveFile).mockClear();
});

// ===== ① 纯函数 =====
describe('单表导出纯函数 tableToCsv / tableToJson', () => {
  it('tableToCsv：BOM 头 + 首行表头=列名（剥掉 :类型后缀）+ 按列名取行值', () => {
    const csv = tableToCsv(DATA, 'appdb.users');
    expect(csv.startsWith('\uFEFF')).toBe(true);
    const lines = csv.slice(1).split('\n');
    expect(lines[0]).toBe('id,name');
    expect(lines[1]).toBe('1,"Alice, ""Admin"""'); // 逗号/引号正确转义
    // 单元格内换行：整体被引号包裹，跨两行
    expect(lines[2]).toBe('2,"Line1');
    expect(lines[3]).toBe('Line2"');
    expect(lines[4]).toBe('3,Bob');
  });

  it('tableToCsv：缺列/缺行定义时不抛错（空表输出仅表头或空行）', () => {
    const csv = tableToCsv({ ...DATA, rows: {} }, 'appdb.users');
    expect(csv.slice(1)).toBe('id,name');
    const empty = tableToCsv({ databases: [], tables: {}, columns: {}, rows: {} }, 'nope.tbl');
    expect(empty).toBe('\uFEFF');
  });

  it('tableToJson：输出可解析 JSON，含 database/table/columns/rows 切片', () => {
    const parsed = JSON.parse(tableToJson(DATA, 'appdb.users'));
    expect(parsed.database).toBe('appdb');
    expect(parsed.table).toBe('users');
    expect(parsed.columns).toEqual(['id:INTEGER', 'name:TEXT']);
    expect(parsed.rows).toHaveLength(3);
    expect(parsed.rows[0].name).toBe('Alice, "Admin"');
  });
});

// ===== ② DbTree UI =====
describe('DbTree 单表导出按钮', () => {
  it('展开库节点后表行出现导出按钮，点击 CSV/JSON 触发 saveFile（文件名/内容/MIME）', () => {
    render(<DbTree data={DATA} />);

    // 展开数据库节点，露出表行
    fireEvent.click(screen.getByText('🗄 数据库 appdb'));
    // 表标题不再内嵌行数，行数由独立徽章显示
    expect(screen.getByText(/表 users/)).toBeTruthy();
    expect(screen.getByText('3 行')).toBeTruthy();

    const csvBtn = screen.getByText('导出 CSV');
    const jsonBtn = screen.getByText('导出 JSON');

    fireEvent.click(csvBtn);
    expect(tauriBridge.saveFile).toHaveBeenCalledTimes(1);
    const [csvName, csvContent, csvMime] = vi.mocked(tauriBridge.saveFile).mock.calls[0];
    expect(csvName).toBe('table_appdb.users.csv');
    expect(String(csvContent).startsWith('\uFEFF')).toBe(true);
    expect(String(csvContent)).toContain('id,name');
    expect(csvMime).toBe('text/csv; charset=utf-8');

    fireEvent.click(jsonBtn);
    expect(tauriBridge.saveFile).toHaveBeenCalledTimes(2);
    const [jsonName, jsonContent, jsonMime] = vi.mocked(tauriBridge.saveFile).mock.calls[1];
    expect(jsonName).toBe('table_appdb.users.json');
    expect(JSON.parse(String(jsonContent)).table).toBe('users');
    expect(jsonMime).toBe('application/json; charset=utf-8');
  });

  it('点击导出按钮不触发节点折叠（表行仍可见）', () => {
    render(<DbTree data={DATA} />);
    fireEvent.click(screen.getByText('🗄 数据库 appdb'));

    fireEvent.click(screen.getByText('导出 CSV'));
    // 表行未因按钮点击被折叠
    expect(screen.getByText(/表 users/)).toBeTruthy();
  });

  it('null 数据渲染占位文案，不出现导出按钮', () => {
    render(<DbTree data={null} />);
    expect(screen.getByText('暂无提取数据')).toBeTruthy();
    expect(screen.queryByText('导出 CSV')).toBeNull();
  });
});
