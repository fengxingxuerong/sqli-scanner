// ReportPage 全局搜索 QA：联动过滤漏洞列表 + 拖库数据树（按库/表/列/单元格值）。
import { describe, it, expect, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import ReportPage from '../pages/ReportPage';
import { useScanStore } from '../store/scanStore';
import type { ReportModel, Vulnerability } from '../shared/types';

function makeReport(): ReportModel {
  const vulns: Vulnerability[] = [
    {
      id: 'v1',
      pointId: 'p_union',
      technique: 'union',
      dbms: 'MySQL',
      riskLevel: 'High',
      payloads: ['u1'],
      description: 'union inject',
      trace: null,
    } as Vulnerability,
    {
      id: 'v2',
      pointId: 'p_bool',
      technique: 'boolean',
      dbms: 'PostgreSQL',
      riskLevel: 'Medium',
      payloads: ['b1'],
      description: 'bool inject',
      trace: null,
    } as Vulnerability,
  ];
  return {
    scanId: 's1',
    target: { baseUrl: 'http://x' } as ReportModel['target'],
    startedAt: '',
    finishedAt: '',
    dbms: null,
    points: [],
    vulns,
    data: {
      databases: ['shop_db', 'user_db'],
      tables: { shop_db: ['orders'], user_db: ['accounts'] },
      columns: {
        'shop_db.orders': ['id:int', 'amount:varchar'],
        'user_db.accounts': ['uid:int', 'email:varchar'],
      },
      rows: {
        'shop_db.orders': [
          { id: 1, amount: '100' },
          { id: 2, amount: '200' },
        ],
        'user_db.accounts': [
          { uid: 1, email: 'a@x.com' },
          { uid: 2, email: 'b@x.com' },
        ],
      },
    },
    riskLevel: 'High',
    summary: {},
  } as ReportModel;
}

beforeEach(() => {
  document.body.innerHTML = '';
  useScanStore.setState({ report: null, status: 'pending' });
});

describe('ReportPage 全局搜索', () => {
  it('默认（无搜索）：两个漏洞 + 两个数据库均渲染', () => {
    useScanStore.setState({ report: makeReport() });
    render(
      <MemoryRouter>
        <ReportPage />
      </MemoryRouter>
    );
    // 漏洞（按 pointId 次级文本定位）
    expect(screen.getByText(/注入点 p_union/)).toBeTruthy();
    expect(screen.getByText(/注入点 p_bool/)).toBeTruthy();
    // 数据库树
    expect(screen.getByText(/🗄 数据库 shop_db/)).toBeTruthy();
    expect(screen.getByText(/🗄 数据库 user_db/)).toBeTruthy();
  });

  it('搜索漏洞词「bool」→ 仅 v2 漏洞可见、v1 隐藏、命中「1 / 2」；数据树无匹配（全局搜索同源）', () => {
    useScanStore.setState({ report: makeReport() });
    const { container } = render(
      <MemoryRouter>
        <ReportPage />
      </MemoryRouter>
    );
    const input = screen.getByLabelText('搜索漏洞 / 数据库 / 表 / 列 / 值') as HTMLInputElement;
    fireEvent.change(input, { target: { value: 'bool' } });
    // 命中片段被 <mark> 拆分，改为用 textContent 判断（避免 getNodeText 跨元素失效）
    expect(container.textContent).toContain('注入点 p_bool');
    expect(container.textContent).not.toContain('注入点 p_union');
    expect(screen.getByText(/命中 1 \/ 2 条漏洞/)).toBeTruthy();
    // 「bool」不匹配任何库/表/列/值 → 数据树整体无匹配
    expect(screen.getByText(/无匹配的数据库/)).toBeTruthy();
    expect(container.textContent).not.toContain('🗄 数据库 shop_db');
    expect(container.textContent).not.toContain('🗄 数据库 user_db');
  });

  it('搜索库名「shop_db」→ 数据树仅 shop_db、user_db 隐藏；该词不匹配任何漏洞 → 漏洞列表空（命中 0 / 2）', () => {
    useScanStore.setState({ report: makeReport() });
    const { container } = render(
      <MemoryRouter>
        <ReportPage />
      </MemoryRouter>
    );
    const input = screen.getByLabelText('搜索漏洞 / 数据库 / 表 / 列 / 值') as HTMLInputElement;
    fireEvent.change(input, { target: { value: 'shop_db' } });
    // 命中片段被 <mark> 拆分，改用 textContent 判断
    expect(container.textContent).toContain('🗄 数据库 shop_db');
    expect(container.textContent).not.toContain('🗄 数据库 user_db');
    // 「shop_db」不匹配任何漏洞字段 → 漏洞列表清空
    expect(screen.getByText(/命中 0 \/ 2 条漏洞/)).toBeTruthy();
    expect(screen.getByText('未发现漏洞')).toBeTruthy();
    expect(container.textContent).not.toContain('注入点 p_union');
    expect(container.textContent).not.toContain('注入点 p_bool');
  });

  it('搜索单元格值「a@x.com」→ 数据树仅 user_db，shop_db 隐藏', () => {
    useScanStore.setState({ report: makeReport() });
    render(
      <MemoryRouter>
        <ReportPage />
      </MemoryRouter>
    );
    const input = screen.getByLabelText('搜索漏洞 / 数据库 / 表 / 列 / 值') as HTMLInputElement;
    fireEvent.change(input, { target: { value: 'a@x.com' } });
    expect(screen.getByText(/🗄 数据库 user_db/)).toBeTruthy();
    expect(screen.queryByText(/🗄 数据库 shop_db/)).toBeNull();
  });

  it('命中高亮：搜索「shop_db」后，数据树命中片段被 <mark> 包裹', () => {
    useScanStore.setState({ report: makeReport() });
    const { container } = render(
      <MemoryRouter>
        <ReportPage />
      </MemoryRouter>
    );
    const input = screen.getByLabelText('搜索漏洞 / 数据库 / 表 / 列 / 值') as HTMLInputElement;
    fireEvent.change(input, { target: { value: 'shop_db' } });
    const marks = container.querySelectorAll('mark');
    expect(marks.length).toBeGreaterThan(0);
    // 命中的库名片段应被高亮
    expect(Array.from(marks).some((m) => m.textContent === 'shop_db')).toBe(true);
  });

  it('清除按钮：搜索「shop_db」后出现「清除搜索」，点击 → 恢复全部漏洞与数据库', () => {
    useScanStore.setState({ report: makeReport() });
    const { container } = render(
      <MemoryRouter>
        <ReportPage />
      </MemoryRouter>
    );
    const input = screen.getByLabelText('搜索漏洞 / 数据库 / 表 / 列 / 值') as HTMLInputElement;
    // 初始（无搜索）不渲染清除按钮
    expect(screen.queryByRole('button', { name: '清除搜索' })).toBeNull();
    fireEvent.change(input, { target: { value: 'shop_db' } });
    expect(screen.getByRole('button', { name: '清除搜索' })).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: '清除搜索' }));
    // 恢复：两漏洞 + 两数据库均在，输入框清空
    expect(container.textContent).toContain('🗄 数据库 shop_db');
    expect(container.textContent).toContain('🗄 数据库 user_db');
    expect(container.textContent).toContain('注入点 p_union');
    expect(container.textContent).toContain('注入点 p_bool');
    expect((screen.getByLabelText('搜索漏洞 / 数据库 / 表 / 列 / 值') as HTMLInputElement).value).toBe('');
  });

  it('Esc：聚焦搜索框输入「bool」后按 Esc → 清空并恢复全部', () => {
    useScanStore.setState({ report: makeReport() });
    const { container } = render(
      <MemoryRouter>
        <ReportPage />
      </MemoryRouter>
    );
    const input = screen.getByLabelText('搜索漏洞 / 数据库 / 表 / 列 / 值') as HTMLInputElement;
    fireEvent.change(input, { target: { value: 'bool' } });
    expect(container.textContent).not.toContain('注入点 p_union');
    fireEvent.keyDown(input, { key: 'Escape' });
    expect((screen.getByLabelText('搜索漏洞 / 数据库 / 表 / 列 / 值') as HTMLInputElement).value).toBe('');
    expect(container.textContent).toContain('注入点 p_union');
    expect(container.textContent).toContain('🗄 数据库 user_db');
  });

  it('按「/」快捷键聚焦全局搜索框', () => {
    useScanStore.setState({ report: makeReport() });
    render(
      <MemoryRouter>
        <ReportPage />
      </MemoryRouter>
    );
    const input = screen.getByLabelText('搜索漏洞 / 数据库 / 表 / 列 / 值') as HTMLInputElement;
    expect(document.activeElement).not.toBe(input);
    fireEvent.keyDown(document, { key: '/' });
    expect(document.activeElement).toBe(input);
  });
});
