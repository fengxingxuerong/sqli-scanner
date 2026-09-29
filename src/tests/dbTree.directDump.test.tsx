// [E2-FIX 2026-09-29] 直拖模式（UI 显式给定 dbs/tables）的提取数据展示回归钉。
//
// 真机 E2 实测的缺陷：extractScope={mode:'dump', dbs:['sqli_lab'], tables:['users']} 走
// UI → REST → 引擎真机拖库，data.rows 里有 5 行 users，但报告页显示「提取数据 (0 库)」、
// 树渲染成空态 —— 因为 data.databases 是空数组，旧判据只认它。修复后库清单从
// databases/tables/rows 并集推导（extractedDbModel），本文件钉住三条行为：
//   ① 纯函数：从 tables/rows 推导库清单（databases 为空时）
//   ② DbTree：直拖数据真实渲染出行内容，不再显示空态
//   ③ 全空数据仍显示空态（判据不得松动到「永远有数据」）
import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import DbTree, { extractedDbModel } from '../components/DbTree';
import type { ExtractedData } from '../shared/types';

vi.mock('../shared/tauriBridge', () => ({
  tauriBridge: { saveFile: vi.fn().mockResolvedValue(undefined), isTauri: false },
}));

// 与真机 E2 拖到的报告同构：databases 空、tables/columns/rows 齐全
const DIRECT_DUMP: ExtractedData = {
  databases: [],
  tables: { sqli_lab: ['users'] },
  columns: { 'sqli_lab.users': ['id', 'username', 'password'] },
  rows: {
    'sqli_lab.users': [
      { id: '1', username: 'admin', password: 'admin123' },
      { id: '2', username: 'bob', password: 'bob456' },
    ],
  },
};

describe('直拖模式（databases=[] 而 rows 有数据）的提取数据展示', () => {
  it('① extractedDbModel：从 tables/rows 推导库清单（含行数键反推的库）', () => {
    expect(extractedDbModel(DIRECT_DUMP)).toEqual([{ db: 'sqli_lab', tables: ['users'] }]);
    // rows-only（tables 也为空）同样能推导出库与表
    const rowsOnly = {
      databases: [],
      tables: {},
      columns: {},
      rows: { 'db1.tbl1': [{ a: 1 }] },
    } as unknown as ExtractedData;
    expect(extractedDbModel(rowsOnly)).toEqual([{ db: 'db1', tables: ['tbl1'] }]);
    // 正常枚举路径不受影响：databases 非空时以它为准
    expect(extractedDbModel({
      databases: ['appdb'],
      tables: { appdb: ['u'] },
      columns: {},
      rows: {},
    })).toEqual([{ db: 'appdb', tables: ['u'] }]);
  });

  it('② DbTree 渲染直拖数据：库/表/数据预览节点可达，空态消失，摘要计数正确', () => {
    render(<DbTree data={DIRECT_DUMP} />);
    expect(screen.getByText(/sqli_lab/)).toBeTruthy();
    expect(screen.queryByText('暂无提取数据')).toBeNull();
    // 库节点默认折叠：展开库 → 表 → 数据预览子节点可达
    fireEvent.click(screen.getByText(/sqli_lab/));
    fireEvent.click(screen.getByText(/users/));
    expect(screen.getByText('数据预览')).toBeTruthy();
    // 摘要计数按推导出的库清单（旧口径会写「共 0 个数据库」）
    expect(screen.getByText(/共 1 个数据库/)).toBeTruthy();
  });

  it('③ 全空数据仍显示空态（判据不松动）', () => {
    render(<DbTree data={{ databases: [], tables: {}, columns: {}, rows: {} }} />);
    expect(screen.getByText('暂无提取数据')).toBeTruthy();
  });
});
