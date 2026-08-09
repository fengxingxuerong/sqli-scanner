// DbTree 受控树 QA：默认库级展开、展开全部/收起全部、预览行数截断、文案准确。
import { describe, it, expect, beforeEach } from 'vitest';
import { render, screen, fireEvent, within } from '@testing-library/react';
import DbTree from '../components/DbTree';
import type { ExtractedData } from '../shared/types';

function makeData(rowCount: number): ExtractedData {
  const rows = Array.from({ length: rowCount }, (_, i) => ({ id: i, name: `n${i}` }));
  return {
    databases: ['db1'],
    tables: { db1: ['users'] },
    columns: { 'db1.users': ['id:int', 'name:varchar'] },
    rows: { 'db1.users': rows },
  };
}

beforeEach(() => {
  document.body.innerHTML = '';
});

describe('DbTree 受控开合', () => {
  it('默认仅展开数据库层级，表/列/数据预览初始收起', () => {
    render(<DbTree data={makeData(5)} />);
    // 库标题可见
    expect(screen.getByText(/🗄 数据库 db1/)).toBeTruthy();
    // 表内「数据预览」默认收起不可见
    expect(screen.queryByText('数据预览')).toBeNull();
    // 顶部展开/收起按钮存在
    expect(screen.getByRole('button', { name: '展开全部' })).toBeTruthy();
    expect(screen.getByRole('button', { name: '收起全部' })).toBeTruthy();
  });

  it('展开全部 → 数据预览可见；收起全部 → 再隐藏', async () => {
    render(<DbTree data={makeData(5)} />);
    fireEvent.click(screen.getByRole('button', { name: '展开全部' }));
    expect(await screen.findByText('数据预览')).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: '收起全部' }));
    expect(screen.queryByText('数据预览')).toBeNull();
  });
});

describe('DbTree 预览截断与文案', () => {
  it('单表预览最多 20 行（25 行数据 → 渲染 20 数据行 + 1 表头）', () => {
    render(<DbTree data={makeData(25)} />);
    // 展开表层级才能看到表格
    fireEvent.click(screen.getByRole('button', { name: '展开全部' }));
    const rows = screen.getAllByRole('row');
    // 1 表头 + 20 数据行
    expect(rows.length).toBe(21);
  });

  it('底部文案准确标注预览上限 20 与后端拖库上限 100', () => {
    render(<DbTree data={makeData(5)} />);
    expect(screen.getByText(/单表预览最多 20 行/)).toBeTruthy();
    expect(screen.getByText(/后端拖库上限 100 行/)).toBeTruthy();
  });
});

describe('DbTree 空数据', () => {
  it('data 为 null 时显示占位文案', () => {
    render(<DbTree data={null} />);
    expect(screen.getByText('暂无提取数据')).toBeTruthy();
  });
});
