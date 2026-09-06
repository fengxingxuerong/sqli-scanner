// P2-S7 拖库数据单独导出测试：
//   ① dumpExport 纯函数：hasDumpData 判定、dumpToCsv（sqlmap --dump 形态：库/表/列/行）、dumpToJson
//   ② ReportExport UI：存在拖库数据时按钮可用并触发下载，无数据时禁用
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { useScanStore } from '../store/scanStore';
import ReportExport from '../components/ReportExport';
import { hasDumpData, dumpToCsv, dumpToJson } from '../shared/dumpExport';
import type { ExtractedData } from '../shared/types';

// mock tauriBridge：断言拖库导出的落盘调用（文件名 / 内容 / MIME）
vi.mock('../shared/tauriBridge', () => ({
  tauriBridge: { saveFile: vi.fn().mockResolvedValue(undefined), isTauri: false },
}));
import { tauriBridge } from '../shared/tauriBridge';

const DATA: ExtractedData = {
  databases: ['appdb'],
  tables: { appdb: ['users', 'orders'] },
  columns: { 'appdb.users': ['id:INTEGER', 'name:TEXT'], 'appdb.orders': ['oid:INTEGER'] },
  rows: {
    'appdb.users': [
      { id: 1, name: 'Alice, "Admin"' },
      { id: 2, name: 'Bob' },
    ],
    'appdb.orders': [{ oid: 100 }],
  },
};

const EMPTY: ExtractedData = { databases: [], tables: {}, columns: {}, rows: {} };

beforeEach(() => {
  vi.mocked(tauriBridge.saveFile).mockClear();
  useScanStore.setState({ scanId: 's1', report: null });
});

// ===== ① 纯函数 =====
describe('P2-S7 dumpExport 纯函数', () => {
  it('hasDumpData：databases/tables/rows 任一非空即为 true，全空/null 为 false', () => {
    expect(hasDumpData(DATA)).toBe(true);
    expect(hasDumpData({ ...DATA, rows: {} })).toBe(true); // 仅库/表也算
    expect(hasDumpData(EMPTY)).toBe(false);
    expect(hasDumpData(null)).toBe(false);
    expect(hasDumpData(undefined)).toBe(false);
  });

  it('dumpToCsv：输出 sqlmap --dump 形态（库清单 + 每表区块：库.表 → 列头 → 行）', () => {
    const csv = dumpToCsv(DATA);
    // BOM 头（Excel 打开不乱码）
    expect(csv.startsWith('\uFEFF')).toBe(true);
    expect(csv).toContain('# 数据库: appdb');
    expect(csv).toContain('## appdb.users');
    expect(csv).toContain('id,name');
    // 单元格含逗号/引号时正确转义
    expect(csv).toContain('"Alice, ""Admin"""');
    expect(csv).toContain('2,Bob');
    expect(csv).toContain('## appdb.orders');
    expect(csv).toContain('100');
    // 表区块顺序与 rows 插入顺序一致（users 在 orders 前）
    expect(csv.indexOf('## appdb.users')).toBeLessThan(csv.indexOf('## appdb.orders'));
  });

  it('dumpToCsv：无行数据时只输出库清单，不抛错', () => {
    const csv = dumpToCsv({ databases: ['a'], tables: {}, columns: {}, rows: {} });
    expect(csv).toContain('# 数据库: a');
    expect(csv).not.toContain('##');
  });

  it('dumpToJson：输出可解析的 JSON，结构与 ExtractedData 同构', () => {
    const json = dumpToJson(DATA);
    const parsed = JSON.parse(json) as ExtractedData;
    expect(parsed.databases).toEqual(['appdb']);
    expect(parsed.rows['appdb.users']).toHaveLength(2);
    expect(parsed.tables.appdb).toContain('orders');
  });
});

// ===== ② ReportExport UI =====
describe('P2-S7 ReportExport 拖库导出入口', () => {
  it('存在拖库数据：按钮可用，点击触发 saveFile（CSV/JSON 各自内容与文件名）', () => {
    useScanStore.setState({ scanId: 's1', report: { scanId: 's1', data: DATA } as any });
    render(<ReportExport />);

    const csvBtn = screen.getByText('拖库 CSV') as HTMLButtonElement;
    const jsonBtn = screen.getByText('拖库 JSON') as HTMLButtonElement;
    expect(csvBtn.disabled).toBe(false);
    expect(jsonBtn.disabled).toBe(false);

    fireEvent.click(csvBtn);
    expect(tauriBridge.saveFile).toHaveBeenCalledTimes(1);
    const [csvName, csvContent, csvMime] = vi.mocked(tauriBridge.saveFile).mock.calls[0];
    expect(csvName).toBe('dump_s1.dump.csv');
    expect(String(csvContent)).toContain('## appdb.users');
    expect(csvMime).toBe('text/csv; charset=utf-8');

    fireEvent.click(jsonBtn);
    expect(tauriBridge.saveFile).toHaveBeenCalledTimes(2);
    const [jsonName, jsonContent, jsonMime] = vi.mocked(tauriBridge.saveFile).mock.calls[1];
    expect(jsonName).toBe('dump_s1.dump.json');
    expect(JSON.parse(String(jsonContent)).databases).toEqual(['appdb']);
    expect(jsonMime).toBe('application/json; charset=utf-8');
  });

  it('无拖库数据：按钮禁用，点击不触发导出', () => {
    useScanStore.setState({ scanId: 's1', report: { scanId: 's1', data: EMPTY } as any });
    render(<ReportExport />);

    const csvBtn = screen.getByText('拖库 CSV') as HTMLButtonElement;
    const jsonBtn = screen.getByText('拖库 JSON') as HTMLButtonElement;
    expect(csvBtn.disabled).toBe(true);
    expect(jsonBtn.disabled).toBe(true);
    expect(screen.getByText(/未提取到拖库数据/)).toBeTruthy();

    fireEvent.click(csvBtn);
    fireEvent.click(jsonBtn);
    expect(tauriBridge.saveFile).not.toHaveBeenCalled();
  });
});
