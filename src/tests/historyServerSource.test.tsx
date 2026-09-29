// ============================================================================
// HistoryPage「服务端为主 + 本地兜底」组件级测试
// ============================================================================
// 为什么还要这一层（historyMerge 已经测过纯函数）：纯函数测的是规则，
// 测不到**UI 有没有真的用上服务端数据** —— 组件里少接一句 useServerHistory，
// 纯函数全绿、页面还是只读本地。这一层钉的是接线与降级两条：
//   ① 服务端返回的行必须出现在页面上（跨设备可见这条价值必须落在 UI 上）
//   ② 服务端拿不到时不能白屏，要退回本地并如实告知
// ============================================================================
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';

const hookState = vi.hoisted(() => ({
  rows: [] as Array<Record<string, unknown>>,
  loading: false,
  error: '',
}));

vi.mock('../hooks/useServerHistory', () => ({
  useServerHistory: () => hookState,
}));

import HistoryPage from '../pages/HistoryPage';
import { useScanStore } from '../store/scanStore';
import type { HistoryRecord, ReportModel } from '../shared/types';

function localRow(scanId: string): HistoryRecord {
  const report = {
    scanId,
    target: { baseUrl: `http://local-${scanId}` },
    vulns: [],
    engine: 'builtin',
  } as unknown as ReportModel;
  return {
    schemaVersion: 1,
    scanId,
    target: `http://local-${scanId}`,
    riskLevel: 'Low',
    finishedAt: '2026-09-29T00:00:00.000Z',
    report,
  };
}

beforeEach(() => {
  hookState.rows = [];
  hookState.loading = false;
  hookState.error = '';
  useScanStore.setState({ history: [], report: null, status: 'pending' });
});

describe('HistoryPage 数据源', () => {
  it('服务端返回的行必须渲染出来，并标为「服务端」', () => {
    hookState.rows = [{
      scanId: 'server-1',
      target: 'http://from-server',
      method: 'GET',
      startedAt: null,
      finishedAt: '2026-09-29T00:00:00.000Z',
      points: 2,
      vulns: 5,
      riskLevel: 'Critical',
      dbms: 'MySQL',
      verdict: 'vulnerability_detected',
      source: 'ledger',
    }];
    render(<MemoryRouter><HistoryPage /></MemoryRouter>);
    expect(screen.getByText('http://from-server')).toBeTruthy();
    expect(screen.getAllByText('服务端').length).toBeGreaterThan(0);
    expect(screen.getByText('5 个漏洞')).toBeTruthy();
  });

  it('没有风险等级时显示「风险未知」，不得编一个等级', () => {
    hookState.rows = [{
      scanId: 'no-risk', target: 'http://no-risk', method: 'GET',
      startedAt: null, finishedAt: null, points: 0, vulns: 0,
      riskLevel: null, dbms: null, verdict: null, source: 'ledger',
    }];
    render(<MemoryRouter><HistoryPage /></MemoryRouter>);
    expect(screen.getByText('风险未知')).toBeTruthy();
  });

  it('纯服务端条目不给删除按钮（删不掉，给按钮等于骗人）；本地条目保留删除', () => {
    hookState.rows = [{
      scanId: 'server-only', target: 'http://server-only', method: 'GET',
      startedAt: null, finishedAt: null, points: 0, vulns: 0,
      riskLevel: 'Low', dbms: null, verdict: null, source: 'ledger',
    }];
    useScanStore.setState({ history: [localRow('local-only')] });
    render(<MemoryRouter><HistoryPage /></MemoryRouter>);
    // 前置：服务端那条必须真的渲染出来了 —— 否则「按钮只有 1 个」也可能来自
    //       服务端行压根没进列表（不接数据源也会绿），这条用例就空转了。
    expect(screen.getByText('http://server-only')).toBeTruthy();
    expect(screen.getByText('http://local-local-only')).toBeTruthy();
    expect(screen.getAllByLabelText('删除').length).toBe(1);
    expect(screen.getAllByText('仅本机').length).toBeGreaterThan(0);
  });

  it('服务端失败时退回本地历史并如实提示（不能出现空页面）', () => {
    hookState.error = 'Network Error';
    useScanStore.setState({ history: [localRow('kept-locally')] });
    render(<MemoryRouter><HistoryPage /></MemoryRouter>);
    expect(screen.getByText(/服务端清单读取失败/)).toBeTruthy();
    expect(screen.getByText('http://local-kept-locally')).toBeTruthy();
  });
});
